import 'dart:convert';
import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../util.dart';

/// Argon2id parameters. Stored inside the keyslot so they can be raised later.
class KdfParams {
  final int opsLimit;
  final int memLimitBytes;
  const KdfParams({required this.opsLimit, required this.memLimitBytes});

  /// 64 MiB, 3 passes: above OWASP's minimum and safe on 3–4 GB phones.
  static const standard = KdfParams(opsLimit: 3, memLimitBytes: 64 * 1024 * 1024);

  /// Only for tests.
  static const fast = KdfParams(opsLimit: 1, memLimitBytes: 8 * 1024 * 1024);
}

/// The master-passphrase-wrapped vault key. Safe to store in plaintext; it is
/// exactly as strong as the passphrase.
class Keyslot {
  final String vaultId;
  final KdfParams params;
  final Uint8List salt;
  final Uint8List wrapped;
  Keyslot(this.vaultId, this.params, this.salt, this.wrapped);

  Map<String, dynamic> toJson() => {
        'v': 1,
        'alg': 'argon2id13+xchacha20poly1305',
        'vault_id': vaultId,
        'ops': params.opsLimit,
        'mem': params.memLimitBytes,
        'salt': base64.encode(salt),
        'wrapped': base64.encode(wrapped),
      };

  String encode() => jsonEncode(toJson());

  static Keyslot fromJson(Map<String, dynamic> j) {
    if (j['v'] != 1) throw const FormatException('unsupported keyslot version');
    return Keyslot(
      j['vault_id'] as String,
      KdfParams(opsLimit: j['ops'] as int, memLimitBytes: j['mem'] as int),
      base64.decode(j['salt'] as String),
      base64.decode(j['wrapped'] as String),
    );
  }

  static Keyslot decode(String s) =>
      fromJson(jsonDecode(s) as Map<String, dynamic>);
}

/// Envelope: version(1) ‖ key_version(1) ‖ nonce(24) ‖ ciphertext+tag.
Uint8List sealEnvelope(
    CryptoBox c, Uint8List key, Uint8List plain, String aad) {
  final nonce = c.randomBytes(CryptoBox.nonceBytes);
  final ct = c.aeadEncrypt(key, nonce, plain, utf8.encode(aad));
  return Uint8List.fromList([1, 1, ...nonce, ...ct]);
}

Uint8List openEnvelope(
    CryptoBox c, Uint8List key, Uint8List envelope, String aad) {
  if (envelope.length < 2 + CryptoBox.nonceBytes + 16 ||
      envelope[0] != 1 ||
      envelope[1] != 1) {
    throw const CryptoException('unsupported or truncated envelope');
  }
  final nonce = Uint8List.sublistView(envelope, 2, 2 + CryptoBox.nonceBytes);
  final ct = Uint8List.sublistView(envelope, 2 + CryptoBox.nonceBytes);
  return c.aeadDecrypt(key, nonce, ct, utf8.encode(aad));
}

/// Holds the vault key while unlocked and performs every encryption the app
/// needs. Key hierarchy:
///
///   passphrase --Argon2id--> KEK --wraps--> VK (random, made once)
///   VK --KDF--> K_local (local secret columns)
///            -> K_sync  (record payloads sent to the server)
///            -> K_id    (keyed hash for deterministic record ids)
class Vault {
  final CryptoBox crypto;
  Vault(this.crypto);

  static const _padBlock = 256;

  Uint8List? _vk, _kLocal, _kSync, _kId;

  bool get isUnlocked => _vk != null;

  void _requireUnlocked() {
    if (_vk == null) throw StateError('vault is locked');
  }

  static String _wrapAad(String vaultId) => 'sshsync/v1/keyslot|$vaultId';

  /// Creates a brand-new vault: random vault key wrapped by [passphrase].
  /// Leaves the vault unlocked.
  Future<Keyslot> create(String passphrase,
      {KdfParams params = KdfParams.standard}) async {
    final vk = crypto.randomBytes(CryptoBox.keyBytes);
    final vaultId = uuidFromBytes(crypto.randomBytes(16));
    final slot = await _wrap(vk, vaultId, passphrase, params);
    _setKey(vk);
    return slot;
  }

  Future<Keyslot> _wrap(Uint8List vk, String vaultId, String passphrase,
      KdfParams params) async {
    final salt = crypto.randomBytes(CryptoBox.saltBytes);
    final kek = await crypto.argon2id(passphrase, salt,
        opsLimit: params.opsLimit, memLimitBytes: params.memLimitBytes);
    try {
      return Keyslot(
          vaultId, params, salt, sealEnvelope(crypto, kek, vk, _wrapAad(vaultId)));
    } finally {
      zero(kek);
    }
  }

  /// Throws [CryptoException] on a wrong passphrase.
  Future<void> unlock(Keyslot slot, String passphrase) async {
    final kek = await crypto.argon2id(passphrase, slot.salt,
        opsLimit: slot.params.opsLimit, memLimitBytes: slot.params.memLimitBytes);
    try {
      _setKey(openEnvelope(crypto, kek, slot.wrapped, _wrapAad(slot.vaultId)));
    } on CryptoException {
      throw const CryptoException('wrong passphrase');
    } finally {
      zero(kek);
    }
  }

  /// Checks a passphrase without changing lock state.
  Future<bool> verify(Keyslot slot, String passphrase) async {
    final probe = Vault(crypto);
    try {
      await probe.unlock(slot, passphrase);
      probe.lock();
      return true;
    } on CryptoException {
      return false;
    }
  }

  /// Unlock with a raw vault key (biometric path: the key comes from the OS
  /// keystore).
  void unlockWithKey(Uint8List vaultKey) {
    if (vaultKey.length != CryptoBox.keyBytes) {
      throw const CryptoException('bad vault key');
    }
    _setKey(Uint8List.fromList(vaultKey));
  }

  /// Copy of the raw vault key, for the OS keystore only.
  Uint8List exportKey() {
    _requireUnlocked();
    return Uint8List.fromList(_vk!);
  }

  /// Re-wraps the same vault key under a new passphrase. No record is
  /// re-encrypted: that is the point of the key-encryption-key design.
  Future<Keyslot> changePassphrase(Keyslot current, String newPassphrase,
      {KdfParams params = KdfParams.standard}) {
    _requireUnlocked();
    return _wrap(_vk!, current.vaultId, newPassphrase, params);
  }

  void _setKey(Uint8List vk) {
    lock();
    _vk = vk;
    _kLocal = crypto.deriveKey(vk, 'sshlocal', 1);
    _kSync = crypto.deriveKey(vk, 'sshsync_', 2);
    _kId = crypto.deriveKey(vk, 'sshrecid', 3);
  }

  void lock() {
    for (final k in [_vk, _kLocal, _kSync, _kId]) {
      if (k != null) zero(k);
    }
    _vk = _kLocal = _kSync = _kId = null;
  }

  Uint8List sealLocal(String recordId, Uint8List plain) {
    _requireUnlocked();
    return sealEnvelope(crypto, _kLocal!, plain, 'local|$recordId');
  }

  Uint8List openLocal(String recordId, Uint8List envelope) {
    _requireUnlocked();
    return openEnvelope(crypto, _kLocal!, envelope, 'local|$recordId');
  }

  /// Encrypts a whole record payload for the server. Padded to 256-byte
  /// multiples so sizes reveal little; bound to the record id so the server
  /// cannot move a blob to another record.
  Uint8List sealSync(String recordId, Uint8List plain) {
    _requireUnlocked();
    return sealEnvelope(
        crypto, _kSync!, crypto.pad(plain, _padBlock), 'sshsync/v1/rec|$recordId');
  }

  Uint8List openSync(String recordId, Uint8List envelope) {
    _requireUnlocked();
    return crypto.unpad(
        openEnvelope(crypto, _kSync!, envelope, 'sshsync/v1/rec|$recordId'),
        _padBlock);
  }

  /// Deterministic record id that the server cannot reverse or guess:
  /// keyed BLAKE2b of [name], formatted as a UUID.
  String deterministicId(String name) {
    _requireUnlocked();
    return uuidFromBytes(crypto.keyedHash(_kId!, utf8.encode(name), 16));
  }

  String randomId() => uuidFromBytes(crypto.randomBytes(16));
}

/// Sync key (SK): 32 random bytes that never reach the server. The keyslot
/// stored on the server is sealed under it, so a server compromise yields
/// nothing a passphrase guess could open.
class SyncKey {
  static const _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  static Uint8List generate(CryptoBox c) => c.randomBytes(CryptoBox.keyBytes);

  static Uint8List sealKeyslot(CryptoBox c, Uint8List sk, Keyslot slot) =>
      sealEnvelope(c, sk, utf8.encode(slot.encode()), 'sshsync/v1/sealed-keyslot');

  static Keyslot openKeyslot(CryptoBox c, Uint8List sk, Uint8List blob) =>
      Keyslot.decode(utf8
          .decode(openEnvelope(c, sk, blob, 'sshsync/v1/sealed-keyslot')));

  /// Base32 text form in groups of four, for typing or a recovery sheet.
  static String format(Uint8List sk) {
    final sb = StringBuffer();
    var bits = 0, value = 0, n = 0;
    for (final b in sk) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) {
        if (n > 0 && n % 4 == 0) sb.write('-');
        sb.write(_alphabet[(value >> (bits - 5)) & 31]);
        bits -= 5;
        n++;
      }
    }
    if (bits > 0) {
      if (n % 4 == 0) sb.write('-');
      sb.write(_alphabet[(value << (5 - bits)) & 31]);
    }
    return sb.toString();
  }

  static Uint8List parse(String text) {
    final clean = text.toUpperCase().replaceAll(RegExp(r'[^A-Z2-7]'), '');
    final out = <int>[];
    var bits = 0, value = 0;
    for (final ch in clean.split('')) {
      value = (value << 5) | _alphabet.indexOf(ch);
      bits += 5;
      if (bits >= 8) {
        out.add((value >> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    if (out.length != CryptoBox.keyBytes) {
      throw const FormatException('sync key must be 52 characters');
    }
    return Uint8List.fromList(out);
  }
}
