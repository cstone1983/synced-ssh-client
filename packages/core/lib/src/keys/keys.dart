import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:pointycastle/export.dart';

import '../crypto/crypto.dart';

/// Thrown when a private key cannot be imported. The message is safe to show
/// to the user: it never contains key material or the passphrase.
class KeyImportException implements Exception {
  final String message;

  /// True when the key is encrypted and the passphrase was missing or wrong.
  final bool wrongPassphrase;

  const KeyImportException(this.message, {this.wrongPassphrase = false});

  @override
  String toString() => 'KeyImportException: $message';
}

/// A private key normalised to unencrypted OpenSSH format, plus its public
/// description.
class KeyInfo {
  /// Unencrypted OpenSSH-format PEM (`-----BEGIN OPENSSH PRIVATE KEY-----`),
  /// loadable by dartssh2 `SSHKeyPair.fromPem`.
  final String privatePem;

  /// authorized_keys line: `<type> <base64> <comment>` (no trailing space when
  /// the comment is empty).
  final String publicLine;

  /// e.g. `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`.
  final String type;

  /// `SHA256:<unpadded base64>`, exactly as `ssh-keygen -lf` prints it.
  final String fingerprint;

  const KeyInfo({
    required this.privatePem,
    required this.publicLine,
    required this.type,
    required this.fingerprint,
  });

  @override
  String toString() => 'KeyInfo($type $fingerprint)';
}

class Keys {
  Keys._();

  /// Generates an Ed25519 key with libsodium (via [c]).
  static KeyInfo generateEd25519(CryptoBox c, {String comment = ''}) {
    final kp = c.ed25519KeyPair();
    if (kp.publicKey.length != 32 || kp.secretKey.length != 64) {
      throw StateError('Unexpected Ed25519 key sizes');
    }
    final pair = OpenSSHEd25519KeyPair(
      Uint8List.fromList(kp.publicKey),
      Uint8List.fromList(kp.secretKey),
      _cleanComment(comment),
    );
    kp.secretKey.fillRange(0, kp.secretKey.length, 0);
    return _info(pair);
  }

  /// Generates an RSA key off the calling isolate (it is slow).
  static Future<KeyInfo> generateRsa(
      {int bits = 4096, String comment = ''}) async {
    if (bits < 2048 || bits > 16384 || bits % 8 != 0) {
      throw ArgumentError.value(
          bits, 'bits', 'must be a multiple of 8 between 2048 and 16384');
    }
    final clean = _cleanComment(comment);
    final pem = await Isolate.run(() => _generateRsaPem(bits, clean));
    return describe(pem);
  }

  /// True for an encrypted OpenSSH PEM, an encrypted legacy PEM, or a PPK
  /// whose `Encryption` is not `none`. False for anything unrecognised.
  static bool needsPassphrase(String text) {
    final t = _normalise(text);
    if (_isPpk(t)) {
      final m = RegExp(r'^Encryption:[ \t]*(.*)$', multiLine: true)
          .firstMatch(t);
      return m != null && m.group(1)!.trim() != 'none';
    }
    final block = _pemBlock(t);
    if (block == null) return false;
    if (block.type == 'ENCRYPTED PRIVATE KEY') return true;
    if (block.type == 'OPENSSH PRIVATE KEY') {
      try {
        return SSHKeyPair.isEncryptedPem(block.text);
      } catch (_) {
        return false;
      }
    }
    return RegExp(r'^(Proc-Type:.*ENCRYPTED|DEK-Info:)', multiLine: true)
        .hasMatch(block.text);
  }

  /// Imports an OpenSSH PEM, a legacy PEM (`RSA PRIVATE KEY`, unencrypted
  /// `EC PRIVATE KEY`), or a PuTTY `.ppk` (v2 or v3). The result is always an
  /// unencrypted OpenSSH PEM.
  ///
  /// A non-empty [comment] replaces the comment stored in the key file.
  static KeyInfo import(String text, {String? passphrase, String comment = ''}) {
    final t = _normalise(text);
    if (t.isEmpty) {
      throw const KeyImportException('The key file is empty.');
    }
    final pass = (passphrase == null || passphrase.isEmpty) ? null : passphrase;
    final OpenSSHKeyPair pair;
    try {
      if (_isPpk(t)) {
        pair = _importPpk(t, pass);
      } else {
        final block = _pemBlock(t);
        if (block == null) {
          if (t.startsWith('ssh-') || t.startsWith('ecdsa-')) {
            throw const KeyImportException(
                'This is a public key. Choose the private key file instead.');
          }
          throw const KeyImportException(
              'Not a recognised private key file (expected an OpenSSH or PEM '
              'private key, or a PuTTY .ppk file).');
        }
        pair = _importPem(block, pass);
      }
    } on KeyImportException {
      rethrow;
    } catch (_) {
      // Deliberately drop the underlying error: it may quote file contents.
      throw const KeyImportException(
          'The key file is damaged or not in a supported format.');
    }
    final clean = _cleanComment(comment);
    return _info(clean.isEmpty ? pair : _withComment(pair, clean));
  }

  /// Derives the public line, type and fingerprint from an unencrypted PEM.
  static KeyInfo describe(String privatePem) {
    if (needsPassphrase(privatePem)) {
      throw const KeyImportException(
          'This key is protected by a passphrase.',
          wrongPassphrase: true);
    }
    return import(privatePem);
  }

  // ---------------------------------------------------------------- PEM

  static OpenSSHKeyPair _importPem(_PemBlock block, String? pass) {
    switch (block.type) {
      case 'OPENSSH PRIVATE KEY':
        final bool encrypted;
        try {
          encrypted = SSHKeyPair.isEncryptedPem(block.text);
        } on UnsupportedError {
          throw const KeyImportException(
              'This OpenSSH key uses an unsupported key derivation function.');
        }
        if (encrypted && pass == null) throw _needPass();
        final List<SSHKeyPair> pairs;
        try {
          pairs = SSHKeyPair.fromPem(block.text, encrypted ? pass : null);
        } on SSHKeyDecryptError {
          if (encrypted) throw _badPass();
          rethrow;
        } on UnsupportedError {
          throw const KeyImportException(
              'This OpenSSH key uses a key type or cipher that is not '
              'supported (supported: Ed25519, RSA, ECDSA P-256/384/521).');
        }
        if (pairs.isEmpty) {
          throw const KeyImportException('The key file contains no keys.');
        }
        final p = pairs.first;
        if (p is! OpenSSHKeyPair) {
          throw const KeyImportException('Unsupported key type.');
        }
        return p;

      case 'RSA PRIVATE KEY':
        final encrypted = block.text.contains('DEK-Info:');
        if (encrypted && pass == null) throw _needPass();
        final SSHKeyPair p;
        try {
          p = SSHKeyPair.fromPem(block.text, encrypted ? pass : null).first;
        } on UnsupportedError {
          throw const KeyImportException(
              'This PEM key is encrypted with an unsupported cipher. Convert '
              'it with "ssh-keygen -p -f <file>" and try again.');
        } catch (_) {
          // A wrong passphrase decrypts to bytes that are not valid ASN.1.
          if (encrypted) throw _badPass();
          rethrow;
        }
        if (p is! RsaPrivateKey) {
          throw const KeyImportException('Unsupported key type.');
        }
        return _rsaPair(p.n, p.e, p.d, p.p, p.q, '',
            unverifiable: encrypted ? _badPass : null);

      case 'EC PRIVATE KEY':
        if (block.text.contains('DEK-Info:')) {
          throw const KeyImportException(
              'Encrypted legacy EC keys are not supported. Convert the key '
              'with "ssh-keygen -p -f <file>" and try again.');
        }
        final SSHKeyPair p;
        try {
          p = SSHKeyPair.fromPem(block.text).first;
        } on UnsupportedError {
          throw const KeyImportException(
              'This EC key uses an unsupported curve (supported: NIST '
              'P-256, P-384, P-521).');
        }
        if (p is! OpenSSHEcdsaKeyPair) {
          throw const KeyImportException('Unsupported key type.');
        }
        return p;

      case 'DSA PRIVATE KEY':
        throw const KeyImportException('DSA keys are not supported.');

      case 'PRIVATE KEY':
      case 'ENCRYPTED PRIVATE KEY':
        throw const KeyImportException(
            'PKCS#8 keys are not supported. Convert the key with '
            '"ssh-keygen -p -f <file>" and try again.');

      default:
        if (block.type.contains('PUBLIC KEY') ||
            block.type.contains('CERTIFICATE')) {
          throw const KeyImportException(
              'This file does not contain a private key.');
        }
        throw const KeyImportException('Unsupported private key format.');
    }
  }

  // ---------------------------------------------------------------- PPK

  static OpenSSHKeyPair _importPpk(String text, String? pass) {
    final ppk = _Ppk.parse(text);
    final encrypted = ppk.encryption != 'none';
    if (ppk.encryption != 'none' && ppk.encryption != 'aes256-cbc') {
      throw const KeyImportException(
          'This PuTTY key uses an unsupported encryption method.');
    }
    if (encrypted && pass == null) throw _needPass();
    final passBytes =
        encrypted ? Uint8List.fromList(utf8.encode(pass!)) : Uint8List(0);

    Uint8List plain;
    Uint8List macKey;
    final Mac mac;
    if (ppk.version == 2) {
      mac = HMac(SHA1Digest(), 64);
      macKey = _sha1([
        Uint8List.fromList(ascii.encode('putty-private-key-file-mac-key')),
        passBytes,
      ]);
      if (encrypted) {
        final key = Uint8List(40)
          ..setRange(0, 20, _sha1([_u32(0), passBytes]))
          ..setRange(20, 40, _sha1([_u32(1), passBytes]));
        plain = _aesCbcDecrypt(
            Uint8List.sublistView(key, 0, 32), Uint8List(16), ppk.privateBlob);
        _zero(key);
      } else {
        plain = ppk.privateBlob;
      }
    } else {
      mac = HMac(SHA256Digest(), 64);
      if (encrypted) {
        final okm = _ppkArgon2(ppk, passBytes);
        plain = _aesCbcDecrypt(Uint8List.sublistView(okm, 0, 32),
            Uint8List.sublistView(okm, 32, 48), ppk.privateBlob);
        macKey = Uint8List.fromList(Uint8List.sublistView(okm, 48, 80));
        _zero(okm);
      } else {
        plain = ppk.privateBlob;
        macKey = Uint8List(0);
      }
    }
    _zero(passBytes);

    // Authenticate before looking at any decrypted content.
    final w = _Writer()
      ..str(utf8.encode(ppk.algorithm))
      ..str(utf8.encode(ppk.encryption))
      ..str(utf8.encode(ppk.comment))
      ..str(ppk.publicBlob)
      ..str(plain);
    mac.init(KeyParameter(macKey));
    final actual = mac.process(w.take());
    _zero(macKey);
    if (!_constantTimeEquals(actual, ppk.mac)) {
      _zero(plain);
      if (encrypted) throw _badPass();
      throw const KeyImportException(
          'The PuTTY key file is damaged or has been modified (integrity '
          'check failed).');
    }

    final pub = _Reader(ppk.publicBlob);
    final priv = _Reader(plain);
    final algorithm = utf8.decode(pub.str());
    if (algorithm != ppk.algorithm) {
      throw const KeyImportException('The PuTTY key file is inconsistent.');
    }
    switch (algorithm) {
      case 'ssh-ed25519':
        final pk = pub.str();
        final seed = priv.str();
        if (pk.length != 32 || seed.length != 32) {
          throw const KeyImportException('Invalid Ed25519 key in PuTTY file.');
        }
        final sk = Uint8List(64)
          ..setRange(0, 32, seed)
          ..setRange(32, 64, pk);
        return OpenSSHEd25519KeyPair(Uint8List.fromList(pk), sk, ppk.comment);
      case 'ssh-rsa':
        final e = pub.mpint();
        final n = pub.mpint();
        final d = priv.mpint();
        final p = priv.mpint();
        final q = priv.mpint();
        return _rsaPair(n, e, d, p, q, ppk.comment);
      case 'ecdsa-sha2-nistp256':
      case 'ecdsa-sha2-nistp384':
      case 'ecdsa-sha2-nistp521':
        final curveId = utf8.decode(pub.str());
        final q = pub.str();
        final d = priv.mpint();
        if ('ecdsa-sha2-$curveId' != algorithm) {
          throw const KeyImportException('Invalid ECDSA key in PuTTY file.');
        }
        final expected = (_curve(curveId).G * d)?.getEncoded(false);
        if (expected == null || !_constantTimeEquals(expected, q)) {
          throw const KeyImportException('Invalid ECDSA key in PuTTY file.');
        }
        return OpenSSHEcdsaKeyPair(curveId, Uint8List.fromList(q), d, ppk.comment);
      default:
        throw KeyImportException(
            'Unsupported key type in PuTTY file: ${_printable(algorithm)} '
            '(supported: Ed25519, RSA, ECDSA P-256/384/521).');
    }
  }

  /// Largest Argon2 memory cost accepted in a .ppk file: 256 MiB, in KiB.
  static const maxPpkArgon2MemoryKiB = 256 * 1024;

  static Uint8List _ppkArgon2(_Ppk ppk, Uint8List pass) {
    final int type;
    switch (ppk.headers['Key-Derivation']) {
      case 'Argon2id':
        type = Argon2Parameters.ARGON2_id;
      case 'Argon2i':
        type = Argon2Parameters.ARGON2_i;
      case 'Argon2d':
        type = Argon2Parameters.ARGON2_d;
      default:
        throw const KeyImportException(
            'This PuTTY key uses an unsupported key derivation function.');
    }
    final memory = int.tryParse(ppk.headers['Argon2-Memory'] ?? '');
    final passes = int.tryParse(ppk.headers['Argon2-Passes'] ?? '');
    final lanes = int.tryParse(ppk.headers['Argon2-Parallelism'] ?? '');
    final saltHex = ppk.headers['Argon2-Salt'];
    if (memory == null || passes == null || lanes == null || saltHex == null) {
      throw const KeyImportException(
          'The PuTTY key file is missing its Argon2 parameters.');
    }
    // Argon2-Memory is in KiB. PuTTYgen's default is 8 MiB; more than
    // 256 MiB could exhaust a phone and is refused before the KDF runs.
    if (memory > maxPpkArgon2MemoryKiB) {
      throw KeyImportException(
          'This PuTTY key needs ${memory ~/ 1024} MiB of memory to unlock, '
          'more than the 256 MiB this app allows. Open it in PuTTYgen and '
          'save it again with a lower Argon2 memory setting (the default is '
          '8 MiB).');
    }
    // Refuse other parameters that would hang the app.
    if (memory < 8 * lanes ||
        passes < 1 ||
        passes > 10000 ||
        lanes < 1 ||
        lanes > 64) {
      throw const KeyImportException(
          'The PuTTY key file uses Argon2 parameters that are out of the '
          'supported range.');
    }
    final salt = _unhex(saltHex);
    final gen = Argon2BytesGenerator()
      ..init(Argon2Parameters(
        type,
        salt,
        desiredKeyLength: 80,
        iterations: passes,
        memory: memory,
        lanes: lanes,
        version: Argon2Parameters.ARGON2_VERSION_13,
      ));
    final out = Uint8List(80);
    gen.deriveKey(pass, 0, out, 0);
    return out;
  }

  static Uint8List _aesCbcDecrypt(Uint8List key, Uint8List iv, Uint8List data) {
    if (data.isEmpty || data.length % 16 != 0) {
      throw const KeyImportException('The PuTTY key file is damaged.');
    }
    final cipher = CBCBlockCipher(AESEngine())
      ..init(false, ParametersWithIV(KeyParameter(key), iv));
    final out = Uint8List(data.length);
    for (var off = 0; off < data.length; off += 16) {
      cipher.processBlock(data, off, out, off);
    }
    return out;
  }

  // ------------------------------------------------------------- helpers

  static KeyImportException _needPass() => const KeyImportException(
      'This key is protected by a passphrase.',
      wrongPassphrase: true);

  static KeyImportException _badPass() =>
      const KeyImportException('Wrong passphrase.', wrongPassphrase: true);

  /// Builds an OpenSSH RSA pair, checking the components are consistent and
  /// computing the CRT coefficient ourselves rather than trusting the file.
  static OpenSSHRsaKeyPair _rsaPair(
      BigInt n, BigInt e, BigInt d, BigInt p, BigInt q, String comment,
      {KeyImportException Function()? unverifiable}) {
    final one = BigInt.one;
    var ok = p > one && q > one && e > one && d > one && p * q == n;
    if (ok) {
      final lambda = _lcm(p - one, q - one);
      ok = (d * e) % lambda == one && p.gcd(q) == one;
    }
    if (!ok) {
      throw (unverifiable ??
          () => const KeyImportException(
              'The RSA key is invalid (its components are inconsistent).'))();
    }
    // OpenSSH wants p > q is not required, but iqmp must be q^-1 mod p.
    return OpenSSHRsaKeyPair(n, e, d, q.modInverse(p), p, q, comment);
  }

  static BigInt _lcm(BigInt a, BigInt b) => (a ~/ a.gcd(b)) * b;

  static ECDomainParameters _curve(String curveId) {
    switch (curveId) {
      case 'nistp256':
        return ECCurve_secp256r1();
      case 'nistp384':
        return ECCurve_secp384r1();
      case 'nistp521':
        return ECCurve_secp521r1();
      default:
        throw const KeyImportException('Unsupported ECDSA curve.');
    }
  }

  static OpenSSHKeyPair _withComment(OpenSSHKeyPair p, String comment) {
    if (p is OpenSSHEd25519KeyPair) {
      return OpenSSHEd25519KeyPair(p.publicKey, p.privateKey, comment);
    }
    if (p is OpenSSHRsaKeyPair) {
      return OpenSSHRsaKeyPair(p.n, p.e, p.d, p.iqmp, p.p, p.q, comment);
    }
    if (p is OpenSSHEcdsaKeyPair) {
      return OpenSSHEcdsaKeyPair(p.curveId, p.q, p.d, comment);
    }
    throw const KeyImportException('Unsupported key type.');
  }

  static KeyInfo _info(OpenSSHKeyPair pair) {
    final blob = pair.toPublicKey().encode();
    final comment = _cleanComment(pair.comment ?? '');
    final line = '${pair.name} ${base64.encode(blob)}';
    final digest = SHA256Digest().process(blob);
    return KeyInfo(
      privatePem: pair.toPem(),
      publicLine: comment.isEmpty ? line : '$line $comment',
      type: pair.name,
      fingerprint: 'SHA256:${base64.encode(digest).replaceAll('=', '')}',
    );
  }

  static String _cleanComment(String c) =>
      c.replaceAll(RegExp(r'[\x00-\x1f\x7f]+'), ' ').trim();

  static String _printable(String s) {
    final t = s.replaceAll(RegExp(r'[^A-Za-z0-9@._-]'), '?');
    return t.length > 40 ? t.substring(0, 40) : t;
  }

  static String _normalise(String text) {
    var t = text.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
    if (t.startsWith('﻿')) t = t.substring(1);
    return t.trim();
  }

  static bool _isPpk(String t) => t.startsWith('PuTTY-User-Key-File-');

  static _PemBlock? _pemBlock(String t) {
    final m = RegExp(r'-----BEGIN ([A-Z0-9 ]+)-----\n[\s\S]*?\n-----END \1-----')
        .firstMatch(t);
    if (m == null) return null;
    final text = m.group(0)!.split('\n').map((l) => l.trim()).join('\n');
    return _PemBlock(m.group(1)!, text);
  }

  static Uint8List _sha1(List<Uint8List> parts) {
    final d = SHA1Digest();
    for (final p in parts) {
      d.update(p, 0, p.length);
    }
    final out = Uint8List(20);
    d.doFinal(out, 0);
    return out;
  }

  static Uint8List _u32(int v) =>
      Uint8List(4)..buffer.asByteData().setUint32(0, v);

  static void _zero(Uint8List b) => b.fillRange(0, b.length, 0);

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  static Uint8List _unhex(String s) {
    if (s.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(s)) {
      throw const KeyImportException('The PuTTY key file is damaged.');
    }
    final out = Uint8List(s.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }
}

String _generateRsaPem(int bits, String comment) {
  final sys = Random.secure();
  final seed = Uint8List.fromList(List.generate(32, (_) => sys.nextInt(256)));
  final rng = FortunaRandom()..seed(KeyParameter(seed));
  final gen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(65537), bits, 64), rng));
  final pair = gen.generateKeyPair();
  final priv = pair.privateKey;
  final p = priv.p!, q = priv.q!;
  return OpenSSHRsaKeyPair(priv.modulus!, priv.publicExponent!,
          priv.privateExponent!, q.modInverse(p), p, q, comment)
      .toPem();
}

class _PemBlock {
  final String type;
  final String text;
  _PemBlock(this.type, this.text);
}

/// Parsed (still encrypted, unauthenticated) PuTTY key file.
class _Ppk {
  final int version;
  final String algorithm;
  final String encryption;
  final String comment;
  final Map<String, String> headers;
  final Uint8List publicBlob;
  final Uint8List privateBlob;
  final Uint8List mac;

  _Ppk(this.version, this.algorithm, this.encryption, this.comment,
      this.headers, this.publicBlob, this.privateBlob, this.mac);

  static const _bad = KeyImportException('The PuTTY key file is damaged.');

  factory _Ppk.parse(String text) {
    final lines = text.split('\n');
    var i = 0;

    (String, String) header() {
      if (i >= lines.length) throw _bad;
      final line = lines[i++];
      final c = line.indexOf(':');
      if (c <= 0) throw _bad;
      var v = line.substring(c + 1);
      if (v.startsWith(' ')) v = v.substring(1);
      return (line.substring(0, c), v);
    }

    Uint8List body(String countText) {
      final n = int.tryParse(countText.trim());
      if (n == null || n < 0 || n > 4096 || i + n > lines.length) throw _bad;
      final b64 = lines.sublist(i, i + n).map((l) => l.trim()).join();
      i += n;
      try {
        return base64.decode(b64);
      } on FormatException {
        throw _bad;
      }
    }

    final first = header();
    final int version;
    switch (first.$1) {
      case 'PuTTY-User-Key-File-2':
        version = 2;
      case 'PuTTY-User-Key-File-3':
        version = 3;
      case 'PuTTY-User-Key-File-1':
        throw const KeyImportException(
            'PuTTY key format version 1 is not supported. Re-save the key '
            'with a current PuTTYgen.');
      default:
        throw const KeyImportException(
            'Unsupported PuTTY key file version.');
    }
    final algorithm = first.$2.trim();

    final headers = <String, String>{};
    String? comment;
    Uint8List? pub, priv, mac;
    while (i < lines.length) {
      if (lines[i].trim().isEmpty) {
        i++;
        continue;
      }
      final (k, v) = header();
      switch (k) {
        case 'Comment':
          comment = v;
        case 'Public-Lines':
          pub = body(v);
        case 'Private-Lines':
          priv = body(v);
        case 'Private-MAC':
          mac = Keys._unhex(v.trim());
        case 'Private-Hash':
          throw const KeyImportException(
              'This PuTTY key file uses an obsolete integrity format.');
        default:
          headers[k] = v.trim();
      }
    }
    final encryption = headers['Encryption'];
    if (encryption == null ||
        comment == null ||
        pub == null ||
        priv == null ||
        mac == null) {
      throw _bad;
    }
    return _Ppk(version, algorithm, encryption, comment, headers, pub, priv, mac);
  }
}

/// SSH wire-format reader (uint32-length-prefixed strings, mpints).
class _Reader {
  final Uint8List _b;
  int _o = 0;
  _Reader(this._b);

  Uint8List str() {
    if (_o + 4 > _b.length) {
      throw const KeyImportException('The key data is truncated.');
    }
    final n = ByteData.sublistView(_b, _o, _o + 4).getUint32(0);
    _o += 4;
    if (n > _b.length - _o) {
      throw const KeyImportException('The key data is truncated.');
    }
    final out = Uint8List.sublistView(_b, _o, _o + n);
    _o += n;
    return out;
  }

  BigInt mpint() {
    final s = str();
    if (s.isNotEmpty && s[0] & 0x80 != 0) {
      throw const KeyImportException('The key data is invalid.');
    }
    var v = BigInt.zero;
    for (final x in s) {
      v = (v << 8) | BigInt.from(x);
    }
    return v;
  }
}

class _Writer {
  final _b = BytesBuilder(copy: true);

  void str(List<int> s) {
    _b.add(Keys._u32(s.length));
    _b.add(s);
  }

  Uint8List take() => _b.takeBytes();
}
