import 'package:sshsync_core/sshsync_core.dart';
import 'package:test/test.dart';

void main() {
  late SodiumCrypto c;
  late Store store;
  late KnownHosts known;

  setUpAll(() async => c = await SodiumCrypto.load());

  setUp(() async {
    final v = Vault(c);
    await v.create('p', params: KdfParams.fast);
    store = Store.memory(v);
    known = KnownHosts(store);
  });

  /// An entry as older versions wrote it: one record per algorithm name.
  void oldEntry(String host, int port, String type, String fp) =>
      store.put(RecordType.knownHost, id: store.vault.deterministicId('known_host|$host|$port|$type'), {
        'host': host, 'port': port, 'key_type': type, 'fingerprint': fp,
        'trusted_at': 1,
      });

  test('every trusted key for host and port counts, whatever its type', () {
    known.trust('Pve.lan', 22, 'ssh-ed25519', 'SHA256:ed');
    expect(known.isTrusted('pve.lan', 22, 'SHA256:ed'), isTrue, reason: 'host is case-insensitive');
    expect(known.isTrusted('pve.lan', 2222, 'SHA256:ed'), isFalse, reason: 'other port');
    expect(known.isTrusted('other', 22, 'SHA256:ed'), isFalse, reason: 'other host');
    expect(known.trustedKeys('pve.lan', 22), hasLength(1));
    expect(known.trustedKeys('pve.lan', 2222), isEmpty);
    expect(known.trustedFamilies('pve.lan', 22), {'ssh-ed25519'});
  });

  test('RSA signature names are one key family', () {
    for (final t in ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']) {
      expect(KnownHosts.keyFamily(t), 'ssh-rsa');
    }
    expect(KnownHosts.keyFamily('ssh-ed25519'), 'ssh-ed25519');
    expect(KnownHosts.keyFamily('ecdsa-sha2-nistp256'), 'ecdsa-sha2-nistp256');
  });

  test('entries from older versions are read without migration', () {
    // One RSA key used to get up to three entries, one per signature name.
    oldEntry('h', 22, 'rsa-sha2-512', 'SHA256:rsa');
    oldEntry('h', 22, 'rsa-sha2-256', 'SHA256:rsa');
    oldEntry('h', 22, 'ssh-rsa', 'SHA256:rsa');
    // And one written before key_type was stored.
    store.put(RecordType.knownHost, id: store.vault.deterministicId('known_host|g|22|ssh-ed25519'),
        {'host': 'g', 'port': 22, 'fingerprint': 'SHA256:g'});

    expect(known.isTrusted('h', 22, 'SHA256:rsa'), isTrue);
    expect(known.trustedFamilies('h', 22), {'ssh-rsa'});
    expect(known.isTrusted('g', 22, 'SHA256:g'), isTrue);
    expect(known.trustedFamilies('g', 22), isEmpty);
  });

  test('trusting a new key replaces every old one, old duplicates included', () {
    oldEntry('h', 22, 'rsa-sha2-512', 'SHA256:rsa');
    oldEntry('h', 22, 'ssh-rsa', 'SHA256:rsa');
    oldEntry('h', 22, 'ssh-ed25519', 'SHA256:ed');
    known.trust('other', 22, 'ssh-ed25519', 'SHA256:keep');

    known.trust('h', 22, 'ecdsa-sha2-nistp256', 'SHA256:new');
    final rows = known.trustedKeys('h', 22);
    expect(rows.map((r) => r.str('fingerprint')), ['SHA256:new']);
    expect(known.isTrusted('h', 22, 'SHA256:rsa'), isFalse);
    expect(known.isTrusted('other', 22, 'SHA256:keep'), isTrue, reason: 'other hosts untouched');
  });

  test('a key replaced earlier can be trusted again', () {
    known.trust('h', 22, 'ssh-ed25519', 'SHA256:a');
    known.trust('h', 22, 'ssh-ed25519', 'SHA256:b');
    known.trust('h', 22, 'ssh-ed25519', 'SHA256:a');
    expect(known.trustedKeys('h', 22).map((r) => r.str('fingerprint')), ['SHA256:a']);
  });

  test('trusting the same key twice keeps one entry', () {
    known.trust('h', 22, 'rsa-sha2-512', 'SHA256:rsa');
    known.trust('h', 22, 'ssh-rsa', 'SHA256:rsa');
    expect(store.list(RecordType.knownHost), hasLength(1));
  });
}
