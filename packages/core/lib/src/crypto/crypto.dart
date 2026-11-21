import 'dart:typed_data';

/// Thrown when decryption or authentication fails (wrong key, wrong
/// passphrase, tampered data). Never carries secret material.
class CryptoException implements Exception {
  final String message;
  const CryptoException(this.message);
  @override
  String toString() => 'CryptoException: $message';
}

/// The only cryptographic primitives the app uses. Implemented by libsodium
/// in [SodiumCrypto]; nothing here is hand-rolled.
abstract class CryptoBox {
  static const keyBytes = 32;
  static const nonceBytes = 24;
  static const saltBytes = 16;

  Uint8List randomBytes(int length);

  /// Argon2id v1.3. Runs off the calling isolate.
  Future<Uint8List> argon2id(
    String passphrase,
    Uint8List salt, {
    required int opsLimit,
    required int memLimitBytes,
  });

  /// XChaCha20-Poly1305-IETF. Returns ciphertext with the tag appended.
  Uint8List aeadEncrypt(
      Uint8List key, Uint8List nonce, Uint8List message, Uint8List aad);

  /// Throws [CryptoException] if authentication fails.
  Uint8List aeadDecrypt(
      Uint8List key, Uint8List nonce, Uint8List cipherText, Uint8List aad);

  /// libsodium crypto_kdf (BLAKE2b). [context] must be exactly 8 ASCII chars.
  Uint8List deriveKey(Uint8List masterKey, String context, int subkeyId);

  /// Keyed BLAKE2b (libsodium generichash with a key).
  Uint8List keyedHash(Uint8List key, Uint8List message, int outLen);

  Uint8List pad(Uint8List data, int blockSize);
  Uint8List unpad(Uint8List data, int blockSize);

  /// Ed25519 key pair: 32-byte public key, 64-byte secret key (seed ‖ public).
  ({Uint8List publicKey, Uint8List secretKey}) ed25519KeyPair();
}
