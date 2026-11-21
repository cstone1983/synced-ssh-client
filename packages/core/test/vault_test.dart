import 'dart:convert';
import 'dart:typed_data';

import 'package:sshsync_core/src/crypto/crypto.dart';
import 'package:sshsync_core/src/crypto/sodium_crypto.dart';
import 'package:sshsync_core/src/vault/vault.dart';
import 'package:test/test.dart';

void main() {
  late SodiumCrypto c;
  setUpAll(() async => c = await SodiumCrypto.load());
  Uint8List b(String s) => utf8.encode(s);

  test('round trip, wrong passphrase, passphrase change', () async {
    final v = Vault(c);
    final slot = await v.create('correct horse', params: KdfParams.fast);
    final sealed = v.sealSync('rec-1', b('hello'));
    final local = v.sealLocal('rec-1', b('pw'));
    v.lock();
    expect(v.isUnlocked, isFalse);
    expect(() => v.sealLocal('x', b('y')), throwsStateError);

    await expectLater(v.unlock(slot, 'wrong'), throwsA(isA<CryptoException>()));
    expect(v.isUnlocked, isFalse);

    await v.unlock(Keyslot.decode(slot.encode()), 'correct horse');
    expect(utf8.decode(v.openSync('rec-1', sealed)), 'hello');
    expect(utf8.decode(v.openLocal('rec-1', local)), 'pw');

    final slot2 = await v.changePassphrase(slot, 'new one', params: KdfParams.fast);
    v.lock();
    await expectLater(v.unlock(slot2, 'correct horse'), throwsA(isA<CryptoException>()));
    await v.unlock(slot2, 'new one');
    expect(utf8.decode(v.openSync('rec-1', sealed)), 'hello');
    expect(await v.verify(slot2, 'new one'), isTrue);
    expect(await v.verify(slot2, 'nope'), isFalse);
  });

  test('tampering anywhere fails; blob bound to record id', () async {
    final v = Vault(c);
    await v.create('p', params: KdfParams.fast);
    final sealed = v.sealSync('rec-1', b('secret payload'));
    for (var i = 0; i < sealed.length; i++) {
      final t = Uint8List.fromList(sealed)..[i] ^= 1;
      expect(() => v.openSync('rec-1', t), throwsA(isA<CryptoException>()), reason: 'byte $i');
    }
    expect(() => v.openSync('rec-2', sealed), throwsA(isA<CryptoException>()));
    expect(() => v.openLocal('rec-1', sealed), throwsA(isA<CryptoException>()));
    expect(() => v.openSync('rec-1', Uint8List(5)), throwsA(isA<CryptoException>()));
  });

  test('payload is padded and non-deterministic', () async {
    final v = Vault(c);
    await v.create('p', params: KdfParams.fast);
    final a = v.sealSync('r', b('a'));
    final a2 = v.sealSync('r', b('a'));
    final long = v.sealSync('r', b('a' * 200));
    expect(a, isNot(equals(a2)));
    expect(a.length, long.length);
    expect((a.length - 2 - 24 - 16) % 256, 0);
  });

  test('deterministic ids are stable per vault and differ across vaults', () async {
    final v = Vault(c), w = Vault(c);
    await v.create('p', params: KdfParams.fast);
    await w.create('p', params: KdfParams.fast);
    expect(v.deterministicId('known_host|a|22|ssh-ed25519'), v.deterministicId('known_host|a|22|ssh-ed25519'));
    expect(v.deterministicId('x'), isNot(w.deterministicId('x')));
    expect(v.deterministicId('x'), matches(RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')));
  });

  test('biometric path: export key and unlock with it', () async {
    final v = Vault(c);
    await v.create('p', params: KdfParams.fast);
    final sealed = v.sealLocal('r', b('x'));
    final key = v.exportKey();
    v.lock();
    v.unlockWithKey(key);
    expect(utf8.decode(v.openLocal('r', sealed)), 'x');
  });

  test('sync key seals the keyslot and round-trips as text', () async {
    final v = Vault(c);
    final slot = await v.create('p', params: KdfParams.fast);
    final sk = SyncKey.generate(c);
    final text = SyncKey.format(sk);
    expect(text.replaceAll('-', '').length, 52);
    expect(SyncKey.parse(text.toLowerCase()), sk);
    final blob = SyncKey.sealKeyslot(c, sk, slot);
    expect(utf8.decode(blob, allowMalformed: true).contains('salt'), isFalse);
    expect(SyncKey.openKeyslot(c, sk, blob).encode(), slot.encode());
    expect(() => SyncKey.openKeyslot(c, SyncKey.generate(c), blob), throwsA(isA<CryptoException>()));
    expect(() => SyncKey.parse('ABCD'), throwsFormatException);
  });

  test('Argon2id is deterministic and salt-dependent', () async {
    final k1 = await c.argon2id('password', Uint8List(16), opsLimit: 1, memLimitBytes: 8 * 1024 * 1024);
    final k2 = await c.argon2id('password', Uint8List(16), opsLimit: 1, memLimitBytes: 8 * 1024 * 1024);
    final k3 = await c.argon2id('password', Uint8List(16)..[0] = 1, opsLimit: 1, memLimitBytes: 8 * 1024 * 1024);
    expect(k1, k2);
    expect(k1, isNot(k3));
    expect(k1.length, 32);
  });
}
