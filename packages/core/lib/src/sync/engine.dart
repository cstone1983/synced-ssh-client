import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../store/schema.dart';
import '../store/store.dart';
import '../vault/vault.dart';
import 'api.dart';
import 'hlc.dart';
import 'merge.dart';

enum SyncPhase { idle, syncing, offline, error, revoked }

class SyncStatus {
  final SyncPhase phase;
  final int? lastSuccessMs;
  final String? error;
  final int pending;

  /// Server time minus device time, in ms (null if unknown).
  final int? clockSkewMs;

  /// Blobs from the server that could not be decrypted in the last run.
  final int unreadable;

  /// The server's keyslot could not be opened with this device's sync key in
  /// the last run. Records still sync; passphrase changes from other devices
  /// cannot reach this one, and this one's are not uploaded, until it is fixed.
  final bool keyslotUnreadable;
  const SyncStatus(this.phase,
      {this.lastSuccessMs,
      this.error,
      this.pending = 0,
      this.clockSkewMs,
      this.unreadable = 0,
      this.keyslotUnreadable = false});

  bool get clockWarning => clockSkewMs != null && clockSkewMs!.abs() > 5 * 60000;
}

/// Exchanges changes with the sync server. Entirely optional: nothing else
/// in the app depends on it, and every failure leaves local data untouched.
class SyncEngine {
  final Store store;
  final SyncApi api;

  /// Sync key. When present, the passphrase-wrapped vault key is kept on the
  /// server sealed under it, so other devices can enroll.
  final Uint8List? syncKey;

  final _status = StreamController<SyncStatus>.broadcast();
  late SyncStatus current;
  Future<bool>? _running;
  Timer? _timer, _debounce;
  StreamSubscription<void>? _sub;
  int _failures = 0;
  DateTime _notBefore = DateTime.fromMillisecondsSinceEpoch(0);

  SyncEngine(this.store, this.api, {this.syncKey}) {
    current = SyncStatus(SyncPhase.idle,
        lastSuccessMs: int.tryParse(store.kvGet('sync_last_success') ?? ''),
        pending: store.pendingCount);
  }

  Vault get _vault => store.vault;
  CryptoBox get _crypto => _vault.crypto;
  Stream<SyncStatus> get status => _status.stream;

  void _set(SyncPhase phase,
      {String? error, int unreadable = 0, bool keyslotUnreadable = false}) {
    final skew = api.lastServerTime == 0
        ? current.clockSkewMs
        : api.lastServerTime - DateTime.now().millisecondsSinceEpoch;
    current = SyncStatus(phase,
        lastSuccessMs: int.tryParse(store.kvGet('sync_last_success') ?? ''),
        error: error,
        pending: store.pendingCount,
        clockSkewMs: skew,
        unreadable: unreadable,
        keyslotUnreadable: keyslotUnreadable);
    if (!_status.isClosed) _status.add(current);
  }

  /// Sync on a timer and shortly after local changes, with backoff on failure.
  void start({Duration interval = const Duration(seconds: 60)}) {
    stop();
    _timer = Timer.periodic(interval, (_) => _auto());
    _sub = store.changes.listen((_) {
      if (_running != null || store.pendingCount == 0) return;
      _debounce?.cancel();
      _debounce = Timer(const Duration(seconds: 2), _auto);
    });
    _auto();
  }

  void _auto() {
    if (DateTime.now().isBefore(_notBefore)) return;
    syncOnce();
  }

  void stop() {
    _timer?.cancel();
    _debounce?.cancel();
    _sub?.cancel();
    _timer = _debounce = null;
    _sub = null;
  }

  void dispose() {
    stop();
    _status.close();
  }

  /// One full cycle: keyslot, pull, push. Returns true on success. Safe to
  /// call at any time; concurrent calls share one run.
  Future<bool> syncOnce() => _running ??= _run().whenComplete(() => _running = null);

  Future<bool> _run() async {
    if (!_vault.isUnlocked || current.phase == SyncPhase.revoked) return false;
    _set(SyncPhase.syncing);
    try {
      final keyslotOk = await _syncKeyslot();
      final unreadable = await _pull();
      await _push();
      store.kvSet('sync_last_success',
          '${DateTime.now().millisecondsSinceEpoch}');
      _failures = 0;
      _notBefore = DateTime.fromMillisecondsSinceEpoch(0);
      _set(SyncPhase.idle,
          unreadable: unreadable, keyslotUnreadable: !keyslotOk);
      return true;
    } on OfflineException catch (e) {
      _fail(SyncPhase.offline, e.message);
    } on ApiException catch (e) {
      if (e.isRevoked) {
        stop();
        _set(SyncPhase.revoked, error: 'This device was revoked.');
      } else {
        _fail(SyncPhase.error, e.message);
      }
    } on StateError catch (e) {
      // Vault locked mid-sync, or a vault mismatch. Not a secret.
      _fail(SyncPhase.error, e.message);
    } catch (e) {
      _fail(SyncPhase.error, 'Sync failed (${e.runtimeType})');
    }
    return false;
  }

  void _fail(SyncPhase phase, String message) {
    _failures++;
    final seconds = (5 * (1 << (_failures - 1).clamp(0, 6))).clamp(5, 300);
    _notBefore = DateTime.now().add(Duration(seconds: seconds));
    _set(phase, error: message);
  }

  // ---- keyslot ----

  /// Mark the local keyslot as changed (after a passphrase change) so the
  /// next sync uploads it.
  static void markKeyslotChanged(Store store) =>
      store.kvSet('keyslot_dirty', '1');

  /// Returns false if the server's keyslot could not be opened. That is a
  /// warning, not a stop: records are sealed with the vault key, not the
  /// keyslot, so they keep syncing. Any device token can replace the keyslot,
  /// so a broken one must not be able to halt sync for everyone.
  Future<bool> _syncKeyslot() async {
    final sk = syncKey;
    final localText = store.kvGet('keyslot');
    if (sk == null || localText == null) return true;
    final local = Keyslot.decode(localText);
    final known = int.tryParse(store.kvGet('keyslot_version') ?? '') ?? 0;
    final dirty = store.kvGet('keyslot_dirty') == '1';
    final remote = await api.getKeyslot();

    Future<bool> upload(int base) async {
      final v = await api.putKeyslot(
          base, SyncKey.sealKeyslot(_crypto, sk, local));
      store.kvSet('keyslot_version', '$v');
      store.kvSet('keyslot_dirty', null);
      return true;
    }

    if (remote == null) return upload(0);
    if (remote.version == known && !dirty) return true;

    final Keyslot theirs;
    try {
      theirs = SyncKey.openKeyslot(_crypto, sk, remote.blob);
    } on CryptoException {
      // Keep using the local keyslot and leave the server's alone: it may
      // belong to someone else, so it is never overwritten from here.
      return false;
    } on FormatException {
      return false;
    } on TypeError {
      return false;
    }
    if (theirs.vaultId != local.vaultId) {
      throw StateError('The server belongs to a different vault.');
    }
    if (dirty) return upload(remote.version);
    // Passphrase was changed on another device: adopt its keyslot. The vault
    // key is unchanged, so nothing needs re-encrypting.
    store.kvSet('keyslot', theirs.encode());
    store.kvSet('keyslot_version', '${remote.version}', notify: true);
    return true;
  }

  // ---- pull / push ----

  /// Returns false if the blob could not be read.
  bool _mergeChange(RemoteChange c) {
    final RecState remote;
    try {
      remote = RecState.decode(
          c.id, utf8.decode(_vault.openSync(c.id, c.blob)));
    } on CryptoException {
      return false;
    } on FormatException {
      return false;
    } on TypeError {
      return false;
    }
    final conflicts = store.mergeRemote(remote, serverSeq: c.seq);
    for (final f in conflicts) {
      _recordConflict(f);
    }
    return true;
  }

  void _recordConflict(FieldConflict f) {
    if (f.recordType == RecordType.conflict) return;
    final id = _vault.deterministicId(
        'conflict|${f.recordId}|${f.field}|${f.losingClock}');
    if (store.syncRow(id) != null) return;
    store.put(RecordType.conflict, id: id, {
      'kind': f.kind,
      'record_id': f.recordId,
      'record_type': f.recordType,
      'field': f.field,
      'winning_value': f.winningValue,
      'losing_value': f.losingValue,
      'snapshot': f.snapshot,
      'winning_device': Hlc.deviceOf(f.winningClock),
      'losing_device': Hlc.deviceOf(f.losingClock),
      'winning_at': Hlc.wallMs(f.winningClock),
      'losing_at': Hlc.wallMs(f.losingClock),
      'created_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  Future<int> _pull() async {
    var cursor = int.tryParse(store.kvGet('sync_cursor') ?? '') ?? 0;
    var unreadable = 0;
    while (true) {
      final r = await api.pull(cursor);
      for (final c in r.changes) {
        if (!_mergeChange(c)) unreadable++;
      }
      cursor = r.cursor;
      store.kvSet('sync_cursor', '$cursor');
      if (!r.hasMore) return unreadable;
    }
  }

  Future<void> _push() async {
    // Each round either cleans records or merges a newer server version, so
    // this terminates; the cap only guards against a misbehaving server.
    for (var round = 0; round < 50; round++) {
      final rows = store.dirtyRows();
      if (rows.isEmpty) return;
      final results = await api.push([
        for (final r in rows)
          PushItem(r.state.id, r.serverSeq, r.state.isDeleted,
              _vault.sealSync(r.state.id, utf8.encode(r.state.encode())))
      ]);
      final byId = {for (final r in rows) r.state.id: r};
      for (final res in results) {
        final row = byId[res.id];
        if (row == null) continue;
        if (res.ok) {
          store.markPushed(row.state, res.seq);
        } else if (!_mergeChange(res.current!)) {
          // The server's copy is unreadable (not written by this vault) or
          // the server has no such record (seq 0, e.g. after a server
          // restore). Re-push on top of whatever it has.
          store.rebase(res.id, res.seq);
        }
      }
    }
    throw StateError('Sync did not settle; will retry.');
  }
}
