import 'dart:convert';

import '../util.dart';
import 'hlc.dart';

/// The full plaintext state of one record: what gets encrypted and synced.
class RecState {
  final String id;
  final String type;
  final Map<String, dynamic> fields;

  /// Field name -> clock of its last write.
  final Map<String, String> clocks;

  /// Non-null once deleted. Deletion is permanent; fields are cleared.
  final String? deleted;

  RecState(this.id, this.type, this.fields, this.clocks, {this.deleted});

  bool get isDeleted => deleted != null;

  String encode() => jsonEncode({'t': type, 'f': fields, 'c': clocks, 'd': deleted});

  static RecState decode(String id, String json) {
    final j = jsonDecode(json) as Map<String, dynamic>;
    final clocks = (j['c'] as Map).map((k, v) => MapEntry(k as String, v as String));
    final deleted = j['d'] as String?;
    if (clocks.values.any((c) => !Hlc.isValid(c)) ||
        (deleted != null && !Hlc.isValid(deleted))) {
      throw const FormatException('bad clock in record');
    }
    return RecState(id, j['t'] as String,
        Map<String, dynamic>.from(j['f'] as Map), clocks,
        deleted: deleted);
  }
}

class FieldConflict {
  /// 'field': same field edited on two devices. 'delete': one device deleted
  /// the record while the other edited it.
  final String kind;
  final String recordId;
  final String recordType;
  final String? field;
  final Object? winningValue;
  final Object? losingValue;
  final String winningClock;
  final String losingClock;

  /// For 'delete': the edited record that lost, so it can be restored.
  final Map<String, dynamic>? snapshot;

  FieldConflict.field(this.recordId, this.recordType, this.field,
      this.winningValue, this.losingValue, this.winningClock, this.losingClock)
      : kind = 'field',
        snapshot = null;

  FieldConflict.delete(this.recordId, this.recordType, this.snapshot,
      this.winningClock, this.losingClock)
      : kind = 'delete',
        field = null,
        winningValue = null,
        losingValue = null;
}

class MergeResult {
  final RecState state;
  final List<FieldConflict> conflicts;

  /// True when the merged state differs from [remote] and must be pushed.
  final bool needsPush;

  /// True when the merged state differs from what was stored locally.
  final bool changedLocal;
  MergeResult(this.state, this.conflicts, this.needsPush, this.changedLocal);
}

/// Field-by-field merge of a local record with a version from the server.
///
/// [synced] holds the clocks of the last server version this device saw; a
/// side has "changed since sync" when its clock for a field differs from it.
/// Per field the later clock wins (so replicas always converge). When both
/// sides changed the same field to different values, the loser is reported
/// as a conflict rather than dropped silently.
MergeResult mergeRecords(
    RecState? local, RecState remote, Map<String, String> synced) {
  if (local == null) return MergeResult(remote, const [], false, true);

  final conflicts = <FieldConflict>[];

  // Deletion wins over edits, but an edit the deleting side never saw is
  // preserved as a conflict.
  if (local.isDeleted || remote.isDeleted) {
    final deleted = maxClock(local.deleted, remote.deleted)!;
    final survivor = local.isDeleted ? remote : local;
    if (!(local.isDeleted && remote.isDeleted)) {
      final unseenEdit =
          survivor.clocks.entries.any((e) => synced[e.key] != e.value);
      // A remote survivor only counts as "edited behind our back" if we had
      // synced this record before; otherwise there is nothing to compare to.
      final survivorChanged = identical(survivor, local)
          ? unseenEdit
          : synced.isNotEmpty && unseenEdit;
      if (survivorChanged && survivor.fields.isNotEmpty) {
        final losing = survivor.clocks.values.reduce((a, b) => maxClock(a, b)!);
        conflicts.add(FieldConflict.delete(survivor.id, survivor.type,
            Map<String, dynamic>.from(survivor.fields), deleted, losing));
      }
    }
    final clocks = <String, String>{};
    for (final k in {...local.clocks.keys, ...remote.clocks.keys}) {
      clocks[k] = maxClock(local.clocks[k], remote.clocks[k])!;
    }
    final state = RecState(local.id, local.type, {}, clocks, deleted: deleted);
    return MergeResult(
        state, conflicts, !_same(state, remote), !_same(state, local));
  }

  final fields = <String, dynamic>{};
  final clocks = <String, String>{};
  for (final f in {...local.clocks.keys, ...remote.clocks.keys}) {
    final cl = local.clocks[f], cr = remote.clocks[f], cs = synced[f];
    if (cr == null || (cl != null && cl.compareTo(cr) >= 0)) {
      // Local wins (or is the only side).
      fields[f] = local.fields[f];
      clocks[f] = cl!;
      if (cr != null &&
          cl != cr &&
          cl != cs &&
          cr != cs &&
          !deepEquals(local.fields[f], remote.fields[f])) {
        conflicts.add(FieldConflict.field(local.id, local.type, f,
            local.fields[f], remote.fields[f], cl, cr));
      }
    } else {
      fields[f] = remote.fields[f];
      clocks[f] = cr;
      if (cl != null &&
          cl != cs &&
          cr != cs &&
          !deepEquals(local.fields[f], remote.fields[f])) {
        conflicts.add(FieldConflict.field(local.id, local.type, f,
            remote.fields[f], local.fields[f], cr, cl));
      }
    }
  }
  final state = RecState(local.id, local.type, fields, clocks);
  return MergeResult(
      state, conflicts, !_same(state, remote), !_same(state, local));
}

bool _same(RecState a, RecState b) =>
    a.deleted == b.deleted &&
    deepEquals(a.clocks, b.clocks) &&
    deepEquals(a.fields, b.fields);
