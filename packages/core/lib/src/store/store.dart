import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sqlite3/sqlite3.dart';

import '../sync/hlc.dart';
import '../sync/merge.dart';
import '../util.dart';
import '../vault/vault.dart';
import 'schema.dart';

/// A record as the UI sees it. Secret fields are present only while the
/// vault is unlocked.
class Rec {
  final String id;
  final String type;
  final Map<String, dynamic> fields;
  const Rec(this.id, this.type, this.fields);

  T? get<T>(String field) => fields[field] as T?;
  String str(String field, [String fallback = '']) =>
      (fields[field] as String?) ?? fallback;
  int integer(String field, [int fallback = 0]) =>
      (fields[field] as num?)?.toInt() ?? fallback;
  bool flag(String field, [bool fallback = false]) =>
      (fields[field] as bool?) ?? fallback;
  List<T> list<T>(String field) =>
      ((fields[field] as List?) ?? const []).cast<T>();
}

/// Internal row: plaintext state plus sync bookkeeping.
class SyncRow {
  final RecState state;
  final Map<String, String> synced;
  final int serverSeq;
  final bool dirty;
  SyncRow(this.state, this.synced, this.serverSeq, this.dirty);
}

class PendingChange {
  final String id;
  final String type;
  final bool deleted;
  final List<String> fields;
  PendingChange(this.id, this.type, this.deleted, this.fields);
}

/// The local database: source of truth for the UI.
///
/// One generic `records` table holds every synced record. Non-secret fields
/// are plain JSON (searchable, visible while locked); secret fields live in
/// an encrypted envelope. `kv` holds device-local settings and state that is
/// never synced.
class Store {
  final Database db;
  final Vault vault;
  late final Hlc hlc;
  final _changes = StreamController<void>.broadcast();

  Store(this.db, this.vault, {int Function()? now}) {
    db.execute('''
      CREATE TABLE IF NOT EXISTS records(
        id TEXT PRIMARY KEY, type TEXT NOT NULL,
        data TEXT NOT NULL, secret BLOB,
        clocks TEXT NOT NULL, synced TEXT NOT NULL DEFAULT '{}',
        deleted TEXT, server_seq INTEGER NOT NULL DEFAULT 0,
        dirty INTEGER NOT NULL DEFAULT 1);
      CREATE INDEX IF NOT EXISTS records_type ON records(type);
      CREATE INDEX IF NOT EXISTS records_dirty ON records(dirty);
      CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    ''');
    var device = kvGet('device_id');
    if (device == null) {
      device = uuidFromBytes(vault.crypto.randomBytes(16)).substring(0, 8);
      kvSet('device_id', device);
    }
    hlc = Hlc(device, now: now, last: kvGet('hlc'));
  }

  static Store open(String path, Vault vault) {
    final db = sqlite3.open(path);
    db.execute('PRAGMA journal_mode=WAL;');
    return Store(db, vault);
  }

  static Store memory(Vault vault, {int Function()? now}) =>
      Store(sqlite3.openInMemory(), vault, now: now);

  /// Fires after every committed change. UI listens and re-reads.
  Stream<void> get changes => _changes.stream;
  void _notify() {
    if (!_changes.isClosed) _changes.add(null);
  }

  String get deviceId => hlc.deviceId;

  void close() {
    _changes.close();
    db.close();
  }

  // ---- key/value (local only) ----

  String? kvGet(String key) {
    final r = db.select('SELECT value FROM kv WHERE key=?', [key]);
    return r.isEmpty ? null : r.first['value'] as String;
  }

  void kvSet(String key, String? value, {bool notify = false}) {
    if (value == null) {
      db.execute('DELETE FROM kv WHERE key=?', [key]);
    } else {
      db.execute(
          'INSERT INTO kv(key,value) VALUES(?,?) '
          'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
          [key, value]);
    }
    if (notify) _notify();
  }

  Map<String, dynamic> kvJson(String key) {
    final v = kvGet(key);
    return v == null ? {} : jsonDecode(v) as Map<String, dynamic>;
  }

  void kvSetJson(String key, Map<String, dynamic> value, {bool notify = true}) =>
      kvSet(key, jsonEncode(value), notify: notify);

  T _tx<T>(T Function() body) {
    db.execute('BEGIN IMMEDIATE');
    try {
      final r = body();
      db.execute('COMMIT');
      return r;
    } catch (_) {
      db.execute('ROLLBACK');
      rethrow;
    }
  }

  String _tick() {
    final c = hlc.next();
    kvSet('hlc', c);
    return c;
  }

  // ---- row <-> state ----

  Map<String, String> _clockMap(Object? json) =>
      (jsonDecode(json as String) as Map).cast<String, String>();

  Map<String, dynamic> _fields(Row r, {required bool withSecrets}) {
    final fields = jsonDecode(r['data'] as String) as Map<String, dynamic>;
    final secret = r['secret'] as Uint8List?;
    if (withSecrets && secret != null) {
      fields.addAll(jsonDecode(utf8.decode(
          vault.openLocal(r['id'] as String, secret))) as Map<String, dynamic>);
    }
    return fields;
  }

  SyncRow _row(Row r) => SyncRow(
        RecState(r['id'] as String, r['type'] as String,
            _fields(r, withSecrets: true), _clockMap(r['clocks']),
            deleted: r['deleted'] as String?),
        _clockMap(r['synced']),
        r['server_seq'] as int,
        (r['dirty'] as int) != 0,
      );

  void _write(RecState s,
      {required Map<String, String> synced,
      required int serverSeq,
      required bool dirty}) {
    final plain = <String, dynamic>{}, secret = <String, dynamic>{};
    s.fields.forEach((k, v) {
      (RecordType.isSecret(s.type, k) ? secret : plain)[k] = v;
    });
    secret.removeWhere((_, v) => v == null);
    final blob = secret.isEmpty
        ? null
        : vault.sealLocal(s.id, utf8.encode(jsonEncode(secret)));
    db.execute(
        'INSERT INTO records(id,type,data,secret,clocks,synced,deleted,server_seq,dirty) '
        'VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
        'data=excluded.data, secret=excluded.secret, clocks=excluded.clocks, '
        'synced=excluded.synced, deleted=excluded.deleted, '
        'server_seq=excluded.server_seq, dirty=excluded.dirty',
        [
          s.id,
          s.type,
          jsonEncode(plain),
          blob,
          jsonEncode(s.clocks),
          jsonEncode(synced),
          s.deleted,
          serverSeq,
          dirty ? 1 : 0
        ]);
  }

  // ---- public record API ----

  /// Live (non-deleted) records of [type].
  List<Rec> list(String type) {
    final rows = db.select(
        'SELECT * FROM records WHERE type=? AND deleted IS NULL', [type]);
    return [
      for (final r in rows)
        Rec(r['id'] as String, type, _fields(r, withSecrets: vault.isUnlocked))
    ];
  }

  Rec? get(String? id) {
    if (id == null) return null;
    final rows =
        db.select('SELECT * FROM records WHERE id=? AND deleted IS NULL', [id]);
    if (rows.isEmpty) return null;
    final r = rows.first;
    return Rec(
        id, r['type'] as String, _fields(r, withSecrets: vault.isUnlocked));
  }

  /// Creates a record, or (when [id] already exists) updates the given fields.
  /// Only fields whose value actually changes get a new clock.
  String put(String type, Map<String, dynamic> fields, {String? id}) {
    final rid = id ?? vault.randomId();
    _tx(() => _apply(rid, type, fields));
    _notify();
    return rid;
  }

  void update(String id, Map<String, dynamic> changes) {
    _tx(() {
      final rows = db.select('SELECT type FROM records WHERE id=?', [id]);
      if (rows.isEmpty) throw StateError('no such record');
      _apply(id, rows.first['type'] as String, changes);
    });
    _notify();
  }

  void _apply(String id, String type, Map<String, dynamic> changes) {
    final rows = db.select('SELECT * FROM records WHERE id=?', [id]);
    final old = rows.isEmpty ? null : _row(rows.first);
    if (old != null && old.state.isDeleted) {
      throw StateError('record was deleted');
    }
    final fields = Map<String, dynamic>.from(old?.state.fields ?? {});
    final clocks = Map<String, String>.from(old?.state.clocks ?? {});
    var changed = old == null;
    changes.forEach((k, v) {
      if (clocks.containsKey(k) && deepEquals(fields[k], v)) return;
      fields[k] = v;
      clocks[k] = _tick();
      changed = true;
    });
    if (!changed) return;
    _write(RecState(id, type, fields, clocks),
        synced: old?.synced ?? {}, serverSeq: old?.serverSeq ?? 0, dirty: true);
  }

  /// Tombstones the record and erases its content, secrets included.
  void delete(String id) {
    _tx(() {
      final rows = db.select('SELECT deleted FROM records WHERE id=?', [id]);
      if (rows.isEmpty || rows.first['deleted'] != null) return;
      db.execute(
          "UPDATE records SET data='{}', secret=NULL, deleted=?, dirty=1 WHERE id=?",
          [_tick(), id]);
    });
    _notify();
  }

  // ---- sync internals ----

  SyncRow? syncRow(String id) {
    final rows = db.select('SELECT * FROM records WHERE id=?', [id]);
    return rows.isEmpty ? null : _row(rows.first);
  }

  List<SyncRow> dirtyRows({int limit = 100}) => [
        for (final r in db.select(
            'SELECT * FROM records WHERE dirty=1 ORDER BY id LIMIT ?', [limit]))
          _row(r)
      ];

  int get pendingCount =>
      db.select('SELECT count(*) AS n FROM records WHERE dirty=1').first['n']
          as int;

  /// Non-secret summary of pending records, for the Sync screen.
  List<PendingChange> pendingSummary() {
    final out = <PendingChange>[];
    for (final r
        in db.select('SELECT * FROM records WHERE dirty=1 ORDER BY type')) {
      final clocks = _clockMap(r['clocks']), synced = _clockMap(r['synced']);
      out.add(PendingChange(
          r['id'] as String, r['type'] as String, r['deleted'] != null, [
        for (final e in clocks.entries)
          if (synced[e.key] != e.value) e.key
      ]));
    }
    return out;
  }

  /// Merges a version from the server ([serverSeq] > 0) or from a backup
  /// ([serverSeq] == 0) into the local record. Returns the conflicts found;
  /// the caller turns them into conflict records.
  List<FieldConflict> mergeRemote(RecState remote, {required int serverSeq}) {
    final conflicts = _tx(() {
      final local = syncRow(remote.id);
      for (final c in remote.clocks.values) {
        hlc.observe(c);
      }
      if (remote.deleted != null) hlc.observe(remote.deleted!);
      kvSet('hlc', hlc.current);
      final m = mergeRecords(local?.state, remote, local?.synced ?? {});
      final fromServer = serverSeq > 0;
      _write(m.state,
          synced: fromServer ? remote.clocks : (local?.synced ?? {}),
          serverSeq: fromServer ? serverSeq : (local?.serverSeq ?? 0),
          dirty: fromServer ? m.needsPush : true);
      return m.conflicts;
    });
    _notify();
    return conflicts;
  }

  /// Marks a pushed record clean, unless it changed again while the push was
  /// in flight.
  void markPushed(RecState pushed, int seq) {
    _tx(() {
      final cur = syncRow(pushed.id);
      if (cur == null) return;
      final unchanged = deepEquals(cur.state.clocks, pushed.clocks) &&
          cur.state.deleted == pushed.deleted;
      _write(cur.state,
          synced: pushed.clocks, serverSeq: seq, dirty: !unchanged);
    });
    _notify();
  }

  /// Re-base a record on a server version we could not read, keeping it
  /// pending so the next push overwrites that version.
  void rebase(String id, int serverSeq) => db.execute(
      'UPDATE records SET server_seq=?, dirty=1 WHERE id=?', [serverSeq, id]);

  /// Forget all server bookkeeping (used when pointing at a new server).
  void resetSyncState() {
    db.execute("UPDATE records SET synced='{}', server_seq=0, dirty=1");
    _notify();
  }

  /// Every record, deleted ones included (for backups).
  List<RecState> exportAll() =>
      [for (final r in db.select('SELECT * FROM records')) _row(r).state];

  void wipe() {
    db.execute('DELETE FROM records; DELETE FROM kv;');
    _notify();
  }
}
