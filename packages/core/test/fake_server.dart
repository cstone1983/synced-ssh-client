import 'dart:typed_data';

import 'package:sshsync_core/sshsync_core.dart';

/// In-memory server with the same contract as the FastAPI one.
class FakeServer {
  final records = <String, RemoteChange>{};
  int seq = 0;
  RemoteKeyslot? keyslot;
  bool offline = false;

  /// Apply the next push but lose the reply.
  bool dropNextPushReply = false;
  final revoked = <String>{};
  int pushCalls = 0;

  SyncApi client(String name) => _Client(this, name);

  /// Everything the server has ever stored, as raw bytes.
  Iterable<Uint8List> get allBlobs => [
        ...records.values.map((r) => r.blob),
        if (keyslot != null) keyslot!.blob
      ];
}

class _Client implements SyncApi {
  final FakeServer s;
  final String name;
  _Client(this.s, this.name);

  @override
  int lastServerTime = 0;

  void _check() {
    if (s.offline) throw OfflineException('offline');
    if (s.revoked.contains(name)) {
      throw ApiException(401, 'device_revoked', 'revoked');
    }
    lastServerTime = DateTime.now().millisecondsSinceEpoch;
  }

  @override
  Future<PullResult> pull(int since, {int limit = 200}) async {
    _check();
    final all = s.records.values.where((r) => r.seq > since).toList()
      ..sort((a, b) => a.seq.compareTo(b.seq));
    final page = all.take(limit).toList();
    return PullResult(
        page, page.isEmpty ? since : page.last.seq, all.length > page.length);
  }

  @override
  Future<List<PushResult>> push(List<PushItem> items) async {
    _check();
    s.pushCalls++;
    final out = <PushResult>[];
    for (final i in items) {
      final cur = s.records[i.id];
      if ((cur?.seq ?? 0) != i.baseSeq) {
        out.add(PushResult(i.id, false, cur!.seq, cur));
      } else {
        s.records[i.id] = RemoteChange(i.id, ++s.seq, i.deleted, i.blob);
        out.add(PushResult(i.id, true, s.seq, null));
      }
    }
    if (s.dropNextPushReply) {
      s.dropNextPushReply = false;
      throw OfflineException('reply lost');
    }
    return out;
  }

  @override
  Future<RemoteKeyslot?> getKeyslot() async {
    _check();
    return s.keyslot;
  }

  @override
  Future<int> putKeyslot(int baseVersion, Uint8List blob) async {
    _check();
    if ((s.keyslot?.version ?? 0) != baseVersion) {
      throw ApiException(409, 'version_conflict', 'stale');
    }
    s.keyslot = RemoteKeyslot(baseVersion + 1, blob);
    return baseVersion + 1;
  }

  @override
  Future<List<DeviceInfo>> devices() async => [];
  @override
  Future<void> revokeDevice(String id) async => s.revoked.add(id);
  @override
  Future<String> rotateToken() async => 't';
  @override
  Future<({String code, int expiresAt})> createEnrollmentCode() async =>
      (code: 'AAAAA-AAAAA', expiresAt: 0);
}
