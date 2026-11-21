import 'dart:convert';
import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../store/store.dart';
import '../sync/merge.dart';
import 'vault.dart';

/// Self-contained encrypted backup. Needs only the passphrase it was made
/// with: no server, no sync key, no existing vault.
///
/// Layout (JSON): magic, version, a keyslot wrapping a random file key under
/// the passphrase (Argon2id), and the record dump encrypted with that key.
class Backup {
  static const magic = 'sshsync-backup';

  static Future<String> export(Store store, String passphrase,
      {KdfParams params = KdfParams.standard}) async {
    final c = store.vault.crypto;
    final dump = jsonEncode([
      for (final s in store.exportAll())
        {'id': s.id, 'rec': s.encode()}
    ]);
    final fileVault = Vault(c);
    final slot = await fileVault.create(passphrase, params: params);
    final key = fileVault.exportKey();
    fileVault.lock();
    final data = sealEnvelope(c, key, utf8.encode(dump), 'sshsync/v1/backup');
    return jsonEncode({
      'magic': magic,
      'v': 1,
      'created_at': DateTime.now().toUtc().toIso8601String(),
      'keyslot': slot.toJson(),
      'data': base64.encode(data),
    });
  }

  /// Decrypts a backup. Throws [CryptoException] on a wrong passphrase or a
  /// modified file, [FormatException] if it is not a backup at all.
  static Future<List<RecState>> read(
      CryptoBox c, String file, String passphrase) async {
    final Map<String, dynamic> j;
    try {
      j = jsonDecode(file) as Map<String, dynamic>;
    } catch (_) {
      throw const FormatException('not a backup file');
    }
    if (j['magic'] != magic || j['v'] != 1) {
      throw const FormatException('not a backup file');
    }
    final fileVault = Vault(c);
    await fileVault.unlock(
        Keyslot.fromJson(j['keyslot'] as Map<String, dynamic>), passphrase);
    final key = fileVault.exportKey();
    fileVault.lock();
    final Uint8List plain = openEnvelope(
        c, key, base64.decode(j['data'] as String), 'sshsync/v1/backup');
    return [
      for (final e in (jsonDecode(utf8.decode(plain)) as List).cast<Map>())
        RecState.decode(e['id'] as String, e['rec'] as String)
    ];
  }

  /// Merges a backup into the (unlocked) local store field by field, exactly
  /// like changes from another device. Returns the number of records read.
  static Future<int> import(Store store, String file, String passphrase) async {
    final records = await read(store.vault.crypto, file, passphrase);
    for (final r in records) {
      store.mergeRemote(r, serverSeq: 0);
    }
    return records.length;
  }
}
