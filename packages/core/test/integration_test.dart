@Tags(['integration'])
library;

// Two real sync engines against the real FastAPI server.
//
// By default this starts the server from ../../server with `uv`. To test a
// server that is already running (for example in Docker), set
// SSHSYNC_TEST_URL, SSHSYNC_TEST_CODE (a fresh enrollment code) and
// optionally SSHSYNC_TEST_DB (path of its SQLite file, for the plaintext scan).

import 'dart:convert';
import 'dart:io';

import 'package:sshsync_core/sshsync_core.dart';
import 'package:test/test.dart';

class Device {
  final Store store;
  final HttpSyncApi api;
  final SyncEngine engine;
  final String serverId;
  Device(this.store, this.api, this.engine, this.serverId);
  Future<bool> sync() => engine.syncOnce();
}

void main() {
  late SodiumCrypto c;
  Process? server;
  late String url, code;
  String? dbPath;
  Directory? tmp;

  setUpAll(() async {
    c = await SodiumCrypto.load();
    final env = Platform.environment;
    if (env['SSHSYNC_TEST_URL'] != null) {
      url = env['SSHSYNC_TEST_URL']!;
      code = env['SSHSYNC_TEST_CODE']!;
      dbPath = env['SSHSYNC_TEST_DB'];
      return;
    }
    tmp = Directory.systemTemp.createTempSync('sshsync-it');
    dbPath = '${tmp!.path}/sshsync.db';
    const port = 18473;
    url = 'http://127.0.0.1:$port';
    server = await Process.start(
        'uv',
        [
          'run', 'uvicorn', 'app.main:create_app', '--factory',
          '--host', '127.0.0.1', '--port', '$port', '--no-access-log'
        ],
        workingDirectory: '../../server',
        environment: {'SSHSYNC_DB_PATH': dbPath!, 'SSHSYNC_RATE_LIMIT': 'off', 'PYTHONUNBUFFERED': '1'});
    final out = StringBuffer();
    server!.stdout.transform(utf8.decoder).listen(out.write);
    server!.stderr.transform(utf8.decoder).listen(out.write);
    final found = RegExp(r'\b([A-HJKMNP-Z2-9]{5}-[A-HJKMNP-Z2-9]{5})\b');
    for (var i = 0; i < 150; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      final m = found.firstMatch(out.toString());
      if (m != null && out.toString().contains('startup complete')) {
        code = m.group(1)!;
        return;
      }
    }
    fail('server did not start:\n$out');
  });

  tearDownAll(() {
    server?.kill();
    tmp?.deleteSync(recursive: true);
  });

  test('two clients against the real server', () async {
    // --- first device creates the vault and enrolls with the bootstrap code
    final va = Vault(c);
    final slot = await va.create('correct horse battery', params: KdfParams.fast);
    final sk = SyncKey.generate(c);
    final ea = await HttpSyncApi.enroll(url, code.toLowerCase(), 'desktop', 'windows');
    final sa = Store.memory(va)..kvSet('keyslot', slot.encode());
    final apiA = HttpSyncApi(url, ea.token);
    final a = Device(sa, apiA, SyncEngine(sa, apiA, syncKey: sk), ea.deviceId);
    expect(await a.sync(), isTrue, reason: a.engine.current.error);

    // The bootstrap code is single use.
    await expectLater(HttpSyncApi.enroll(url, code, 'x', 'other'),
        throwsA(isA<ApiException>().having((e) => e.code, 'code', 'invalid_code')));

    // No webhook is set up here, so the server refuses to send codes.
    await expectLater(HttpSyncApi.requestEnrollmentCode(url, 'phone', 'android'),
        throwsA(isA<ApiException>().having((e) => e.code, 'code', 'not_available')));

    // --- second device: code from A, sync key from the "QR", then passphrase
    final invite = await apiA.createEnrollmentCode();
    final eb = await HttpSyncApi.enroll(url, invite.code, 'phone', 'android');
    expect(eb.vaultId, ea.vaultId);
    final apiB = HttpSyncApi(url, eb.token);
    final remote = (await apiB.getKeyslot())!;
    final slotB = SyncKey.openKeyslot(c, SyncKey.parse(SyncKey.format(sk)), remote.blob);
    final vb = Vault(c);
    await expectLater(vb.unlock(slotB, 'wrong passphrase'), throwsA(isA<CryptoException>()));
    await vb.unlock(slotB, 'correct horse battery');
    final sb = Store.memory(vb)
      ..kvSet('keyslot', slotB.encode())
      ..kvSet('keyslot_version', '${remote.version}');
    final b = Device(sb, apiB, SyncEngine(sb, apiB, syncKey: sk), eb.deviceId);

    const needles = ['pve-needle-host', '10.99.88.77', 'needle-user', 'Needle-Passw0rd', 'NEEDLEKEYBODY', 'needle-tag', 'needle-group'];

    // (a) records added on A appear on B
    final group = a.store.put('group', {'name': 'needle-group'});
    final cred = a.store.put('credential', {
      'label': 'main', 'username': 'needle-user', 'password': 'Needle-Passw0rd',
      'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----\nNEEDLEKEYBODY\n-----END OPENSSH PRIVATE KEY-----',
    });
    final host = a.store.put('host', {
      'nickname': 'pve-needle-host', 'hostname': '10.99.88.77', 'port': 22,
      'credential_id': cred, 'group_id': group, 'tags': ['needle-tag'], 'notes': '',
    });
    a.store.put('known_host', {'host': '10.99.88.77', 'port': 22, 'key_type': 'ssh-ed25519', 'fingerprint': 'SHA256:needlefp'},
        id: a.store.vault.deterministicId('known_host|10.99.88.77|22|ssh-ed25519'));
    expect(await a.sync(), isTrue, reason: a.engine.current.error);
    expect(await b.sync(), isTrue, reason: b.engine.current.error);
    expect(b.store.get(host)!.str('nickname'), 'pve-needle-host');
    expect(b.store.get(cred)!.str('password'), 'Needle-Passw0rd');
    expect(b.store.list('known_host').single.str('fingerprint'), 'SHA256:needlefp');
    expect(b.store.list('group').single.str('name'), 'needle-group');

    // (b) both edit while unsynced; different fields merge, same field conflicts
    a.store.update(host, {'nickname': 'pve-needle-host-A', 'port': 2222});
    // Same-millisecond edits are ordered by device id; make B clearly later.
    await Future<void>.delayed(const Duration(milliseconds: 20));
    b.store.update(host, {'nickname': 'pve-needle-host-B', 'notes': 'from phone'});
    await a.sync();
    await b.sync();
    await a.sync();
    for (final d in [a, b]) {
      final h = d.store.get(host)!;
      expect(h.integer('port'), 2222);
      expect(h.str('notes'), 'from phone');
      expect(h.str('nickname'), 'pve-needle-host-B');
      final conflict = d.store.list('conflict').single;
      expect(conflict.str('field'), 'nickname');
      expect(conflict.fields['losing_value'], 'pve-needle-host-A');
      expect(d.store.pendingCount, 0);
    }

    // (c) delete on A removes on B
    a.store.delete(group);
    await a.sync();
    await b.sync();
    expect(b.store.get(group), isNull);

    // (d) the server's database holds none of the plaintext
    if (dbPath != null) {
      final dir = File(dbPath!).parent;
      final files = dir.listSync().whereType<File>().where((f) => f.path.startsWith(dbPath!));
      expect(files, isNotEmpty);
      for (final f in files) {
        final raw = latin1.decode(f.readAsBytesSync());
        for (final n in [...needles, 'correct horse battery', 'from phone', 'nickname']) {
          expect(raw.contains(n), isFalse, reason: '$n found in ${f.path}');
          expect(raw.contains(base64.encode(utf8.encode(n)).replaceAll('=', '')), isFalse);
        }
      }
    }

    // devices, token rotation, revocation
    final devices = await apiA.devices();
    expect(devices.map((d) => d.name).toSet(), {'desktop', 'phone'});
    expect(devices.singleWhere((d) => d.current).id, a.serverId);
    final old = apiB.token;
    await apiB.rotateToken();
    await expectLater(HttpSyncApi(url, old).devices(), throwsA(isA<ApiException>()));
    expect(await b.sync(), isTrue);

    await apiA.revokeDevice(b.serverId);
    b.store.put('host', {'nickname': 'after-revoke'});
    expect(await b.sync(), isFalse);
    expect(b.engine.current.phase, SyncPhase.revoked);
    expect(b.store.list('host'), hasLength(2), reason: 'revocation does not touch local data');

    // server stopped: the client stays fully usable and catches up later
    if (server != null) {
      server!.kill();
      await server!.exitCode;
      final offlineHost = a.store.put('host', {'nickname': 'made-offline'});
      a.store.update(host, {'notes': 'edited offline'});
      expect(await a.sync(), isFalse);
      expect(a.engine.current.phase, SyncPhase.offline);
      expect(a.store.get(offlineHost)!.str('nickname'), 'made-offline');
      expect(a.store.get(cred)!.str('password'), 'Needle-Passw0rd');
      expect(a.store.pendingCount, 2);
    }
  }, timeout: const Timeout(Duration(minutes: 2)));
}
