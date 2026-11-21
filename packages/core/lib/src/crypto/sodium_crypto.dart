import 'dart:isolate';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'crypto.dart';

/// [CryptoBox] backed by libsodium.
class SodiumCrypto implements CryptoBox {
  final SodiumSumo _s;
  SodiumCrypto._(this._s);

  static SodiumCrypto? _instance;

  /// Loads libsodium once. Call at startup before anything else.
  static Future<SodiumCrypto> load() async =>
      _instance ??= SodiumCrypto._(await SodiumSumoInit.init());

  T _withKey<T>(Uint8List key, T Function(SecureKey k) fn) {
    final k = SecureKey.fromList(_s, key);
    try {
      return fn(k);
    } finally {
      k.dispose();
    }
  }

  @override
  Uint8List randomBytes(int length) => _s.randombytes.buf(length);

  @override
  Future<Uint8List> argon2id(String passphrase, Uint8List salt,
      {required int opsLimit, required int memLimitBytes}) {
    // A fresh isolate: 64 MiB of Argon2 must not freeze the UI.
    return Isolate.run(() async {
      final s = await SodiumSumoInit.init();
      final key = s.crypto.pwhash.callStr(
        outLen: CryptoBox.keyBytes,
        password: passphrase,
        salt: salt,
        opsLimit: opsLimit,
        memLimit: memLimitBytes,
        alg: CryptoPwhashAlgorithm.argon2id13,
      );
      try {
        return key.extractBytes();
      } finally {
        key.dispose();
      }
    });
  }

  @override
  Uint8List aeadEncrypt(
          Uint8List key, Uint8List nonce, Uint8List message, Uint8List aad) =>
      _withKey(
          key,
          (k) => _s.crypto.aeadXChaCha20Poly1305IETF.encrypt(
              message: message, nonce: nonce, key: k, additionalData: aad));

  @override
  Uint8List aeadDecrypt(
      Uint8List key, Uint8List nonce, Uint8List cipherText, Uint8List aad) {
    try {
      return _withKey(
          key,
          (k) => _s.crypto.aeadXChaCha20Poly1305IETF.decrypt(
              cipherText: cipherText, nonce: nonce, key: k, additionalData: aad));
    } catch (_) {
      throw const CryptoException('decryption failed');
    }
  }

  @override
  Uint8List deriveKey(Uint8List masterKey, String context, int subkeyId) =>
      _withKey(masterKey, (k) {
        final sub = _s.crypto.kdf.deriveFromKey(
            masterKey: k,
            context: context,
            subkeyId: BigInt.from(subkeyId),
            subkeyLen: CryptoBox.keyBytes);
        try {
          return sub.extractBytes();
        } finally {
          sub.dispose();
        }
      });

  @override
  Uint8List keyedHash(Uint8List key, Uint8List message, int outLen) => _withKey(
      key, (k) => _s.crypto.genericHash(message: message, outLen: outLen, key: k));

  @override
  Uint8List pad(Uint8List data, int blockSize) => _s.pad(data, blockSize);

  @override
  Uint8List unpad(Uint8List data, int blockSize) {
    try {
      return _s.unpad(data, blockSize);
    } catch (_) {
      throw const CryptoException('bad padding');
    }
  }

  @override
  ({Uint8List publicKey, Uint8List secretKey}) ed25519KeyPair() {
    final kp = _s.crypto.sign.keyPair();
    try {
      return (publicKey: kp.publicKey, secretKey: kp.secretKey.extractBytes());
    } finally {
      kp.secretKey.dispose();
    }
  }
}
