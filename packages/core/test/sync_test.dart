import 'dart:convert';

import 'package:sshsync_core/sshsync_core.dart';
import 'package:test/test.dart';

import 'fake_server.dart';

class Device {
  final Store store;
  final SyncEngine engine;
  Device(this.store, this.engine);
  Future<bool> sync() => engine.syncOnce();
}

void main() {
  late SodiumCrypto c;
  late FakeServer server;
  late Vault first;
  late Keyslot slot;
  var clock = 1000000;

  setUpAll(() async => c = await SodiumCrypto.load());

  /// A device sharing the same vault key, as after enrollment.
  Device device(String name, {bool withSyncKey = false}) {
    final v = Vault(c)..unlockWithKey(first.exportKey());
    final s = Store.memory(v, now: () => clock += 10);
    s.kvSet('keyslot', slot.encode());
    return Device(s, SyncEngine(s, server.client(name)));
  }

  setUp(() async {
    server = FakeServer();
    first = Vault(c);
    slot = await first.create('passphrase', params: KdfParams.fast);
  });

  test('(a) host added on A appears on B', () async {
    final a = device('a'), b = device('b');
    final id = a.store.put('host', {'nickname': 'pve', 'hostname': '10.0.0.2', 'port': 22});
    expect(a.store.pendingCount, 1);
    expect(await a.sync(), isTrue);
    expect(a.store.pendingCount, 0);
    expect(await b.sync(), isTrue);
    expect(b.store.get(id)!.fields, {'nickname': 'pve', 'hostname': '10.0.0.2', 'port': 22});
    expect(b.store.pendingCount, 0);
  });

  test('(b) offline edits: different fields merge, same field conflicts', () async {
    final a = device('a'), b = device('b');
    final id = a.store.put('host', {'nickname': 'pve', 'hostname': '10.0.0.2', 'port': 22, 'notes': ''});
    await a.sync();
    await b.sync();

    server.offline = true;
    a.store.update(id, {'nickname': 'proxmox', 'port': 2222});
    b.store.update(id, {'nickname': 'hypervisor', 'notes': 'rack 1'});
    expect(await a.sync(), isFalse);
    expect(a.engine.current.phase, SyncPhase.offline);
    expect(a.store.get(id)!.str('nickname'), 'proxmox', reason: 'usable offline');

    server.offline = false;
    await a.sync();
    await b.sync();
    await a.sync();

    for (final d in [a, b]) {
      final h = d.store.get(id)!;
      expect(h.integer('port'), 2222);
      expect(h.str('notes'), 'rack 1');
      expect(h.str('nickname'), 'hypervisor', reason: 'later write wins');
      final conflicts = d.store.list('conflict');
      expect(conflicts, hasLength(1), reason: 'surfaced on both devices');
      expect(conflicts.single.str('field'), 'nickname');
      expect(conflicts.single.fields['losing_value'], 'proxmox');
      expect(conflicts.single.fields['winning_value'], 'hypervisor');
      expect(d.store.pendingCount, 0);
    }

    // Resolving on A ("use the other value") reaches B.
    final conflict = a.store.list('conflict').single;
    a.store.update(id, {'nickname': conflict.fields['losing_value']});
    a.store.delete(conflict.id);
    await a.sync();
    await b.sync();
    expect(b.store.get(id)!.str('nickname'), 'proxmox');
    expect(b.store.list('conflict'), isEmpty);
  });

  test('(c) delete on A removes on B and erases content', () async {
    final a = device('a'), b = device('b');
    final id = a.store.put('credential', {'label': 'root', 'username': 'root', 'password': 'hunter2'});
    await a.sync();
    await b.sync();
    expect(b.store.get(id)!.str('password'), 'hunter2');
    a.store.delete(id);
    await a.sync();
    await b.sync();
    expect(b.store.get(id), isNull);
    expect(b.store.list('credential'), isEmpty);
    final row = b.store.db.select('SELECT data, secret FROM records WHERE id=?', [id]).first;
    expect(row['data'], '{}');
    expect(row['secret'], isNull);
  });

  test('(d) server never holds plaintext; local secrets are encrypted at rest', () async {
    final a = device('a');
    const needles = ['pve-secret-host', '10.9.8.7', 'rootuser', 'hunter2!', 'PRIVATE-KEY-BODY', 'homelab-tag'];
    final cred = a.store.put('credential', {
      'label': 'main', 'username': 'rootuser', 'password': 'hunter2!',
      'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE-KEY-BODY\n-----END OPENSSH PRIVATE KEY-----'
    });
    a.store.put('host', {'nickname': 'pve-secret-host', 'hostname': '10.9.8.7', 'credential_id': cred, 'tags': ['homelab-tag']});
    a.store.put('known_host', {'host': '10.9.8.7', 'port': 22, 'fingerprint': 'SHA256:abc'},
        id: a.store.vault.deterministicId('known_host|10.9.8.7|22|ssh-ed25519'));
    await a.sync();
    expect(server.records, hasLength(3));
    final haystack = [
      ...server.allBlobs.map((b) => latin1.decode(b)),
      ...server.allBlobs.map(base64.encode),
      server.records.keys.join(' ')
    ].join('\n');
    for (final n in needles) {
      expect(haystack.contains(n), isFalse, reason: n);
    }
    expect(haystack.contains('host'), isFalse, reason: 'record types hidden');

    final localRows = a.store.db.select('SELECT data, secret FROM records').map((r) => '${r['data']}${latin1.decode(r['secret'] as List<int>? ?? [])}').join();
    expect(localRows.contains('hunter2!'), isFalse);
    expect(localRows.contains('PRIVATE-KEY-BODY'), isFalse);
    expect(localRows.contains('pve-secret-host'), isTrue, reason: 'metadata is plaintext locally by design');
  });

  test('locked vault: non-secret fields readable, secrets absent, no sync', () async {
    final a = device('a');
    final id = a.store.put('credential', {'label': 'x', 'username': 'u', 'password': 'p'});
    a.store.vault.lock();
    expect(a.store.get(id)!.fields, {'label': 'x', 'username': 'u'});
    expect(await a.sync(), isFalse);
    expect(server.records, isEmpty);
  });

  test('outbox replay: lost push reply is retried without duplicates or conflicts', () async {
    final a = device('a'), b = device('b');
    final id = a.store.put('host', {'nickname': 'n1'});
    server.dropNextPushReply = true;
    expect(await a.sync(), isFalse);
    expect(a.store.pendingCount, 1, reason: 'still in the outbox');
    expect(server.records, hasLength(1), reason: 'server applied it');
    expect(await a.sync(), isTrue);
    expect(a.store.pendingCount, 0);
    expect(a.store.list('conflict'), isEmpty);
    expect(server.records, hasLength(1));
    await b.sync();
    expect(b.store.get(id)!.str('nickname'), 'n1');
  });

  test('edit made while a push is in flight stays pending', () async {
    final a = device('a');
    final id = a.store.put('host', {'nickname': 'n1'});
    final f = a.sync();
    a.store.update(id, {'nickname': 'n2'});
    await f;
    await a.sync();
    final b = device('b');
    await b.sync();
    expect(b.store.get(id)!.str('nickname'), 'n2');
    expect(a.store.pendingCount, 0);
  });

  test('unchanged writes do not create pending changes', () async {
    final a = device('a');
    final id = a.store.put('host', {'nickname': 'n', 'port': 22});
    await a.sync();
    a.store.update(id, {'nickname': 'n', 'port': 22});
    expect(a.store.pendingCount, 0);
    a.store.update(id, {'port': 23});
    expect(a.store.pendingSummary().single.fields, ['port']);
  });

  test('delete vs edit across devices: deleted everywhere, edit restorable', () async {
    final a = device('a'), b = device('b');
    final id = a.store.put('host', {'nickname': 'n', 'port': 22});
    await a.sync();
    await b.sync();
    a.store.delete(id);
    b.store.update(id, {'port': 2200});
    await a.sync();
    await b.sync();
    await a.sync();
    for (final d in [a, b]) {
      expect(d.store.get(id), isNull);
      final c = d.store.list('conflict').single;
      expect(c.str('kind'), 'delete');
      expect(c.fields['snapshot'], {'nickname': 'n', 'port': 2200});
    }
  });

  test('same known host trusted offline on two devices becomes one record', () async {
    final a = device('a'), b = device('b');
    for (final d in [a, b]) {
      d.store.put('known_host', {'host': 'h', 'port': 22, 'key_type': 'ssh-ed25519', 'fingerprint': 'SHA256:x'},
          id: d.store.vault.deterministicId('known_host|h|22|ssh-ed25519'));
    }
    await a.sync();
    await b.sync();
    await a.sync();
    expect(a.store.list('known_host'), hasLength(1));
    expect(b.store.list('known_host'), hasLength(1));
    expect(a.store.list('conflict'), isEmpty);
    expect(server.records.length, 1);
  });

  test('paging: more records than one pull page', () async {
    final a = device('a'), b = device('b');
    for (var i = 0; i < 450; i++) {
      a.store.put('host', {'nickname': 'h$i'});
    }
    expect(await a.sync(), isTrue);
    expect(await b.sync(), isTrue);
    expect(b.store.list('host'), hasLength(450));
  });

  test('unreadable blobs from the server are skipped, not fatal', () async {
    final a = device('a');
    final rogue = Vault(c);
    await rogue.create('other', params: KdfParams.fast);
    await server.client('x').push([PushItem('11111111-1111-4111-8111-111111111111', 0, false, rogue.sealSync('11111111-1111-4111-8111-111111111111', utf8.encode('{}')))]);
    a.store.put('host', {'nickname': 'ok'});
    expect(await a.sync(), isTrue);
    expect(a.engine.current.unreadable, 1);
    expect(a.store.list('host'), hasLength(1));
  });

  test('revoked device stops syncing and reports it', () async {
    final a = device('a');
    a.store.put('host', {'nickname': 'x'});
    server.revoked.add('a');
    expect(await a.sync(), isFalse);
    expect(a.engine.current.phase, SyncPhase.revoked);
    expect(a.store.list('host'), hasLength(1), reason: 'local data untouched');
  });

  test('keyslot: uploaded sealed, passphrase change propagates', () async {
    final sk = SyncKey.generate(c);
    Device dev(String n) {
      final v = Vault(c)..unlockWithKey(first.exportKey());
      final s = Store.memory(v);
      s.kvSet('keyslot', slot.encode());
      return Device(s, SyncEngine(s, server.client(n), syncKey: sk));
    }

    final a = dev('a'), b = dev('b');
    await a.sync();
    expect(server.keyslot!.version, 1);
    expect(latin1.decode(server.keyslot!.blob).contains('salt'), isFalse);
    await b.sync();

    final slot2 = await a.store.vault.changePassphrase(slot, 'new passphrase', params: KdfParams.fast);
    a.store.kvSet('keyslot', slot2.encode());
    SyncEngine.markKeyslotChanged(a.store);
    await a.sync();
    expect(server.keyslot!.version, 2);
    await b.sync();
    final onB = Keyslot.decode(b.store.kvGet('keyslot')!);
    expect(await Vault(c).verify(onB, 'new passphrase'), isTrue);
    expect(await Vault(c).verify(onB, 'passphrase'), isFalse);

    // A device with the wrong sync key refuses the server.
    final v = Vault(c)..unlockWithKey(first.exportKey());
    final s = Store.memory(v)..kvSet('keyslot', slot.encode());
    final wrong = SyncEngine(s, server.client('w'), syncKey: SyncKey.generate(c));
    expect(await wrong.syncOnce(), isFalse);
    expect(wrong.current.phase, SyncPhase.error);
  });

  test('backup: round trip into a fresh vault, wrong passphrase and tampering fail', () async {
    final a = device('a');
    final cred = a.store.put('credential', {'label': 'l', 'username': 'u', 'password': 'pw-in-backup'});
    final gone = a.store.put('host', {'nickname': 'gone'});
    a.store.delete(gone);
    final file = await Backup.export(a.store, 'backup pass', params: KdfParams.fast);
    expect(file.contains('pw-in-backup'), isFalse);

    final v = Vault(c);
    await v.create('another device', params: KdfParams.fast);
    final fresh = Store.memory(v);
    await expectLater(Backup.import(fresh, file, 'wrong'), throwsA(isA<CryptoException>()));
    final j = jsonDecode(file) as Map<String, dynamic>;
    final data = base64.decode(j['data'] as String);
    data[40] ^= 1;
    await expectLater(Backup.import(fresh, jsonEncode({...j, 'data': base64.encode(data)}), 'backup pass'),
        throwsA(isA<CryptoException>()));
    await expectLater(Backup.import(fresh, 'not json', 'x'), throwsFormatException);

    expect(await Backup.import(fresh, file, 'backup pass'), 2);
    expect(fresh.get(cred)!.str('password'), 'pw-in-backup');
    expect(fresh.get(gone), isNull);
    expect(fresh.pendingCount, 2, reason: 'restored records sync out');
  });

  test('url policy: https required, http only for explicitly allowed LAN', () {
    expect(UrlPolicy.check('https://sync.example.com', allowInsecureLan: false), isNull);
    expect(UrlPolicy.check('http://sync.example.com', allowInsecureLan: true), isNotNull);
    expect(UrlPolicy.check('http://8.8.8.8:8080', allowInsecureLan: true), isNotNull);
    expect(UrlPolicy.check('http://10.10.11.5:8080', allowInsecureLan: false), isNotNull);
    expect(UrlPolicy.check('http://10.10.11.5:8080', allowInsecureLan: true), isNull);
    expect(UrlPolicy.check('http://192.168.1.4', allowInsecureLan: true), isNull);
    expect(UrlPolicy.check('http://172.32.0.1', allowInsecureLan: true), isNotNull);
    expect(UrlPolicy.check('http://sync.lan', allowInsecureLan: true), isNull);
    expect(UrlPolicy.check('http://localhost:8080', allowInsecureLan: true), isNull);
    expect(UrlPolicy.check('ftp://x', allowInsecureLan: true), isNotNull);
    expect(UrlPolicy.check('nonsense', allowInsecureLan: true), isNotNull);
  });
}
