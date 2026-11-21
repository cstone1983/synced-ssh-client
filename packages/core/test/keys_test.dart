@Timeout(Duration(minutes: 5))
library;

import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:sshsync_core/src/crypto/sodium_crypto.dart';
import 'package:sshsync_core/src/keys/keys.dart';
import 'package:test/test.dart';

bool _has(String tool) {
  try {
    return Process.runSync('which', [tool]).exitCode == 0;
  } catch (_) {
    return false;
  }
}

final bool hasKeygen = _has('ssh-keygen');
final bool hasPuttygen = _has('puttygen');
final String? skipKeygen = hasKeygen ? null : 'ssh-keygen is not installed';
final String? skipPutty = (hasKeygen && hasPuttygen)
    ? null
    : 'puttygen and/or ssh-keygen is not installed';

const pass = 'correct horse battery';

late Directory tmp;
var _n = 0;

String path(String name) => '${tmp.path}/$name';

String run(String exe, List<String> args) {
  final r = Process.runSync(exe, args);
  if (r.exitCode != 0) {
    fail('$exe ${args.join(' ')} failed (${r.exitCode}): ${r.stderr}');
  }
  return (r.stdout as String).trim();
}

/// Generates a key with ssh-keygen and returns its private key path.
String keygen(String type,
    {int? bits, String passphrase = '', String comment = 'test@host', bool pem = false}) {
  final f = path('k${_n++}');
  run('ssh-keygen', [
    '-q',
    '-t', type,
    if (bits != null) ...['-b', '$bits'],
    if (pem) ...['-m', 'PEM'],
    if (passphrase.isNotEmpty) ...['-a', '4'],
    '-N', passphrase,
    '-C', comment,
    '-f', f,
  ]);
  return f;
}

String expectedPublic(String keyPath) =>
    File('$keyPath.pub').readAsStringSync().trim();

String expectedFingerprint(String keyPath) =>
    run('ssh-keygen', ['-lf', '$keyPath.pub']).split(' ')[1];

/// Writes [pem] to a 0600 file and asks ssh-keygen to load it.
String keygenPublicOf(String pem) {
  final f = path('out${_n++}');
  File(f).writeAsStringSync(pem);
  run('chmod', ['600', f]);
  return run('ssh-keygen', ['-y', '-f', f]);
}

/// Checks a KeyInfo against what ssh-keygen says about the original key.
void check(KeyInfo info, String keyPath, String type) {
  final pub = expectedPublic(keyPath);
  expect(info.type, type);
  expect(info.publicLine, pub);
  expect(info.fingerprint, expectedFingerprint(keyPath));
  expect(info.privatePem, startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'));
  expect(Keys.needsPassphrase(info.privatePem), isFalse);

  // Loadable by dartssh2, unencrypted.
  final pairs = SSHKeyPair.fromPem(info.privatePem);
  expect(pairs, hasLength(1));
  expect(pairs.first.name, type);

  // Accepted by OpenSSH itself, and it derives the same public key.
  expect(keygenPublicOf(info.privatePem), pub);

  // describe() round-trips.
  final d = Keys.describe(info.privatePem);
  expect(d.publicLine, info.publicLine);
  expect(d.fingerprint, info.fingerprint);
  expect(d.type, type);
}

String puttygen(String keyPath,
    {required int version, String oldPass = '', String newPass = '', String params = ''}) {
  final out = path('p${_n++}.ppk');
  final args = <String>[keyPath, '-O', 'private', '-o', out];
  if (oldPass.isNotEmpty) {
    final f = path('old${_n++}');
    File(f).writeAsStringSync(oldPass);
    args.addAll(['--old-passphrase', f]);
  }
  if (newPass.isNotEmpty) {
    final f = path('new${_n++}');
    File(f).writeAsStringSync(newPass);
    args.addAll(['--new-passphrase', f]);
  }
  args.addAll(['--ppk-param', 'version=$version${params.isEmpty ? '' : ',$params'}']);
  run('puttygen', args);
  return File(out).readAsStringSync();
}

Matcher throwsImport({bool? wrongPassphrase}) => throwsA(isA<KeyImportException>()
    .having((e) => e.wrongPassphrase, 'wrongPassphrase',
        wrongPassphrase ?? anything)
    .having((e) => e.message, 'message', isNotEmpty));

/// Replaces one base64 character on body line [lineAfter] lines after the
/// header that starts with [header].
String flip(String ppk, String header, {int lineAfter = 1}) {
  final lines = ppk.split('\n');
  final i = lines.indexWhere((l) => l.startsWith(header)) + lineAfter;
  final l = lines[i];
  final c = l[5] == 'A' ? 'B' : 'A';
  lines[i] = l.substring(0, 5) + c + l.substring(6);
  return lines.join('\n');
}

void main() {
  setUpAll(() => tmp = Directory.systemTemp.createTempSync('sshsync_keys_'));
  tearDownAll(() => tmp.deleteSync(recursive: true));

  const types = <(String, int?, String)>[
    ('ed25519', null, 'ssh-ed25519'),
    ('rsa', 2048, 'ssh-rsa'),
    ('ecdsa', 256, 'ecdsa-sha2-nistp256'),
    ('ecdsa', 384, 'ecdsa-sha2-nistp384'),
    ('ecdsa', 521, 'ecdsa-sha2-nistp521'),
  ];

  group('generate', () {
    test('ed25519 validates with ssh-keygen', () async {
      final c = await SodiumCrypto.load();
      final k = Keys.generateEd25519(c, comment: 'me@phone');
      expect(k.type, 'ssh-ed25519');
      expect(k.publicLine, matches(r'^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\S+ me@phone$'));
      expect(k.fingerprint, matches(r'^SHA256:[A-Za-z0-9+/]{43}$'));
      expect(SSHKeyPair.fromPem(k.privatePem).single.name, 'ssh-ed25519');
      final other = Keys.generateEd25519(c);
      expect(other.fingerprint, isNot(k.fingerprint));
      expect(other.publicLine.split(' '), hasLength(2));

      if (!hasKeygen) return;
      expect(keygenPublicOf(k.privatePem), k.publicLine);
      final pub = path('gen-ed.pub')..let((p) => File(p).writeAsStringSync('${k.publicLine}\n'));
      final l = run('ssh-keygen', ['-lf', pub]).split(' ');
      expect(l[0], '256');
      expect(l[1], k.fingerprint);
    });

    test('rsa validates with ssh-keygen', () async {
      final k = await Keys.generateRsa(bits: 2048, comment: 'rsa key');
      expect(k.type, 'ssh-rsa');
      expect(k.publicLine, endsWith(' rsa key'));
      expect(SSHKeyPair.fromPem(k.privatePem).single.name, 'ssh-rsa');
      await expectLater(Keys.generateRsa(bits: 512), throwsArgumentError);

      if (!hasKeygen) return;
      expect(keygenPublicOf(k.privatePem), k.publicLine);
      final pub = path('gen-rsa.pub')..let((p) => File(p).writeAsStringSync('${k.publicLine}\n'));
      final l = run('ssh-keygen', ['-lf', pub]).split(' ');
      expect(l[0], '2048');
      expect(l[1], k.fingerprint);
    });
  });

  group('OpenSSH PEM', () {
    for (final (t, bits, name) in types) {
      test('$name unencrypted', () {
        final f = keygen(t, bits: bits);
        final text = File(f).readAsStringSync();
        expect(Keys.needsPassphrase(text), isFalse);
        check(Keys.import(text), f, name);
        // A passphrase supplied for an unencrypted key is ignored.
        check(Keys.import(text, passphrase: 'unused'), f, name);
      }, skip: skipKeygen);

      test('$name encrypted', () {
        final f = keygen(t, bits: bits, passphrase: pass);
        final text = File(f).readAsStringSync();
        expect(Keys.needsPassphrase(text), isTrue);
        check(Keys.import(text, passphrase: pass), f, name);
        expect(() => Keys.import(text, passphrase: 'nope'),
            throwsImport(wrongPassphrase: true));
        expect(() => Keys.import(text), throwsImport(wrongPassphrase: true));
        expect(() => Keys.describe(text), throwsImport(wrongPassphrase: true));
      }, skip: skipKeygen);
    }

    test('default bcrypt rounds, CRLF line endings, comment override', () {
      final f = path('k${_n++}');
      run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', pass, '-C', 'orig', '-f', f]);
      final text = File(f).readAsStringSync().replaceAll('\n', '\r\n');
      final k = Keys.import('\n  $text\n\n', passphrase: pass, comment: 'new name');
      expect(k.publicLine, expectedPublic(f).replaceAll(' orig', ' new name'));
      expect(k.fingerprint, expectedFingerprint(f));
      expect(keygenPublicOf(k.privatePem), k.publicLine);
    }, skip: skipKeygen);
  });

  group('legacy PEM', () {
    test('RSA PRIVATE KEY unencrypted', () {
      final f = keygen('rsa', bits: 2048, pem: true, comment: '');
      final text = File(f).readAsStringSync();
      expect(text, startsWith('-----BEGIN RSA PRIVATE KEY-----'));
      expect(Keys.needsPassphrase(text), isFalse);
      final k = Keys.import(text, comment: 'legacy');
      final pub = expectedPublic(f).split(' ').take(2).join(' ');
      expect(k.publicLine, '$pub legacy');
      expect(k.fingerprint, expectedFingerprint(f));
      expect(keygenPublicOf(k.privatePem), '$pub legacy');
      expect(SSHKeyPair.fromPem(k.privatePem).single.name, 'ssh-rsa');
    }, skip: skipKeygen);

    test('RSA PRIVATE KEY encrypted', () {
      final f = keygen('rsa', bits: 2048, pem: true, passphrase: pass, comment: '');
      final text = File(f).readAsStringSync();
      expect(text, contains('DEK-Info:'));
      expect(Keys.needsPassphrase(text), isTrue);
      final k = Keys.import(text, passphrase: pass);
      final pub = expectedPublic(f).split(' ').take(2).join(' ');
      expect(k.publicLine, pub);
      expect(k.fingerprint, expectedFingerprint(f));
      expect(keygenPublicOf(k.privatePem), pub);
      expect(() => Keys.import(text, passphrase: 'nope'),
          throwsImport(wrongPassphrase: true));
      expect(() => Keys.import(text), throwsImport(wrongPassphrase: true));
    }, skip: skipKeygen);

    test('EC PRIVATE KEY unencrypted', () {
      final f = keygen('ecdsa', bits: 256, pem: true, comment: '');
      final text = File(f).readAsStringSync();
      expect(text, startsWith('-----BEGIN EC PRIVATE KEY-----'));
      final k = Keys.import(text);
      final pub = expectedPublic(f).split(' ').take(2).join(' ');
      expect(k.type, 'ecdsa-sha2-nistp256');
      expect(k.publicLine, pub);
      expect(k.fingerprint, expectedFingerprint(f));
      expect(keygenPublicOf(k.privatePem), pub);
    }, skip: skipKeygen);

    test('encrypted EC PRIVATE KEY is rejected with a clear message', () {
      final f = keygen('ecdsa', bits: 256, pem: true, passphrase: pass);
      final text = File(f).readAsStringSync();
      expect(Keys.needsPassphrase(text), isTrue);
      expect(() => Keys.import(text, passphrase: pass),
          throwsImport(wrongPassphrase: false));
    }, skip: skipKeygen);
  });

  group('PuTTY PPK', () {
    for (final version in [2, 3]) {
      // Small Argon2 cost keeps the pure-Dart KDF fast in tests.
      final fast = version == 3 ? 'memory=1024,passes=2' : '';
      for (final (t, bits, name) in types) {
        test('v$version $name unencrypted', () {
          final f = keygen(t, bits: bits);
          final ppk = puttygen(f, version: version);
          expect(ppk, startsWith('PuTTY-User-Key-File-$version: $name'));
          expect(Keys.needsPassphrase(ppk), isFalse);
          check(Keys.import(ppk), f, name);
        }, skip: skipPutty);

        test('v$version $name encrypted', () {
          final f = keygen(t, bits: bits);
          final ppk = puttygen(f, version: version, newPass: pass, params: fast);
          expect(ppk, contains('Encryption: aes256-cbc'));
          expect(Keys.needsPassphrase(ppk), isTrue);
          check(Keys.import(ppk, passphrase: pass), f, name);
          expect(() => Keys.import(ppk, passphrase: 'nope'),
              throwsImport(wrongPassphrase: true));
          expect(() => Keys.import(ppk), throwsImport(wrongPassphrase: true));
          expect(() => Keys.import(ppk, passphrase: ''),
              throwsImport(wrongPassphrase: true));
        }, skip: skipPutty);
      }
    }

    for (final kdf in ['argon2id', 'argon2i', 'argon2d']) {
      test('v3 $kdf', () {
        final f = keygen('ed25519');
        final ppk = puttygen(f,
            version: 3,
            newPass: pass,
            params: 'kdf=$kdf,memory=2048,passes=3,parallelism=2');
        expect(ppk.toLowerCase(), contains('key-derivation: $kdf'));
        check(Keys.import(ppk, passphrase: pass), f, 'ssh-ed25519');
        expect(() => Keys.import(ppk, passphrase: '${pass}x'),
            throwsImport(wrongPassphrase: true));
      }, skip: skipPutty);
    }

    test('v3 with puttygen default Argon2 parameters, CRLF, non-ASCII', () {
      final f = keygen('ed25519', comment: 'clé@hôte');
      const p = 'pässwörd ✓';
      final ppk = puttygen(f, version: 3, newPass: p).replaceAll('\n', '\r\n');
      check(Keys.import(ppk, passphrase: p), f, 'ssh-ed25519');
    }, skip: skipPutty);

    test('v2 encrypted from an encrypted OpenSSH key', () {
      final f = keygen('rsa', bits: 2048, passphrase: pass);
      final ppk = puttygen(f, version: 2, oldPass: pass, newPass: 'other pass');
      check(Keys.import(ppk, passphrase: 'other pass'), f, 'ssh-rsa');
    }, skip: skipPutty);

    test('tampering is rejected', () {
      final f = keygen('ed25519');
      for (final version in [2, 3]) {
        final ppk = puttygen(f, version: version);
        expect(Keys.import(ppk).fingerprint, expectedFingerprint(f));
        // One flipped byte in the private body, public body, or comment.
        expect(() => Keys.import(flip(ppk, 'Private-Lines')),
            throwsImport(wrongPassphrase: false));
        expect(() => Keys.import(flip(ppk, 'Public-Lines')),
            throwsImport(wrongPassphrase: false));
        expect(() => Keys.import(ppk.replaceFirst('Comment: ', 'Comment: x')),
            throwsImport(wrongPassphrase: false));
        expect(() => Keys.import(flip(ppk, 'Private-MAC', lineAfter: 0)),
            throwsImport());
        // Truncated file.
        expect(() => Keys.import(ppk.substring(0, ppk.indexOf('Private-MAC'))),
            throwsImport(wrongPassphrase: false));

        final enc = puttygen(f,
            version: version,
            newPass: pass,
            params: version == 3 ? 'memory=1024,passes=2' : '');
        expect(Keys.import(enc, passphrase: pass).fingerprint,
            expectedFingerprint(f));
        expect(() => Keys.import(flip(enc, 'Private-Lines'), passphrase: pass),
            throwsImport());
        expect(() => Keys.import(flip(enc, 'Public-Lines'), passphrase: pass),
            throwsImport());
      }
    }, skip: skipPutty);

    test('swapping the public blob of another key is rejected', () {
      final a = puttygen(keygen('rsa', bits: 2048), version: 3);
      final b = puttygen(keygen('rsa', bits: 2048), version: 3);
      String pubOf(String s) =>
          s.substring(s.indexOf('Public-Lines'), s.indexOf('Private-Lines'));
      expect(() => Keys.import(a.replaceFirst(pubOf(a), pubOf(b))),
          throwsImport(wrongPassphrase: false));
    }, skip: skipPutty);

    test('absurd Argon2 parameters are refused without running the KDF', () {
      final f = keygen('ed25519');
      final ppk = puttygen(f, version: 3, newPass: pass, params: 'memory=1024,passes=2');
      final big = ppk.replaceFirst('Argon2-Memory: 1024', 'Argon2-Memory: 99999999999');
      expect(() => Keys.import(big, passphrase: pass),
          throwsImport(wrongPassphrase: false));
    }, skip: skipPutty);

    for (final t in ['ed448', 'dsa']) {
      test('unsupported key type $t', () {
        final out = path('u${_n++}.ppk');
        final empty = path('empty${_n++}')..let((p) => File(p).writeAsStringSync(''));
        run('puttygen', [
          '-t', t,
          if (t == 'dsa') ...['-b', '2048'],
          '-o', out,
          '--new-passphrase', empty,
        ]);
        expect(
            () => Keys.import(File(out).readAsStringSync()),
            throwsA(isA<KeyImportException>()
                .having((e) => e.wrongPassphrase, 'wrongPassphrase', isFalse)
                .having((e) => e.message, 'message', contains('Unsupported key type'))));
      }, skip: skipPutty);
    }
  });

  group('rejects', () {
    test('garbage', () {
      for (final g in [
        '',
        '   \n',
        'hello world',
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMRjelTtK/bisPV+wwhvwn1a5OJpXmfyfLOXRTuPxbu7 me',
        '-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64!!\n-----END OPENSSH PRIVATE KEY-----',
        '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----',
        '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----',
        '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----',
        '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----',
        '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
        'PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n',
        'PuTTY-User-Key-File-9: ssh-ed25519\n',
        'PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: x\n'
            'Public-Lines: 99\nAAAA\nPrivate-Lines: 1\nAAAA\nPrivate-MAC: zz',
      ]) {
        expect(() => Keys.import(g), throwsImport(wrongPassphrase: false),
            reason: 'input: ${g.split('\n').first}');
        expect(Keys.needsPassphrase(g), isFalse);
      }
    });

    test('messages never contain the passphrase or key material', () {
      final f = keygen('ed25519', passphrase: pass);
      final text = File(f).readAsStringSync();
      final body = text.split('\n')[1];
      for (final attempt in ['hunter2-secret', null]) {
        try {
          Keys.import(text, passphrase: attempt);
          fail('should have thrown');
        } on KeyImportException catch (e) {
          expect(e.toString(), isNot(contains('hunter2')));
          expect(e.toString(), isNot(contains(body)));
        }
      }
      final damaged = text.replaceFirst(body, body.substring(0, 30));
      try {
        Keys.import(damaged, passphrase: 'hunter2-secret');
        fail('should have thrown');
      } on KeyImportException catch (e) {
        expect(e.toString(), isNot(contains('hunter2')));
        expect(e.toString(), isNot(contains(body.substring(0, 30))));
      }
    }, skip: skipKeygen);
  });
}

extension<T> on T {
  void let(void Function(T) f) => f(this);
}
