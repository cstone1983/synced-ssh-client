import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

class ApiException implements Exception {
  final int status;
  final String code;
  final String message;
  ApiException(this.status, this.code, this.message);
  bool get isRevoked => code == 'device_revoked';
  bool get isUnauthorized => status == 401;
  @override
  String toString() => 'ApiException($status $code): $message';
}

/// Thrown when the server could not be reached at all.
class OfflineException implements Exception {
  final String message;
  OfflineException(this.message);
  @override
  String toString() => message;
}

class RemoteChange {
  final String id;
  final int seq;
  final bool deleted;
  final Uint8List blob;
  RemoteChange(this.id, this.seq, this.deleted, this.blob);
}

class PushItem {
  final String id;
  final int baseSeq;
  final bool deleted;
  final Uint8List blob;
  PushItem(this.id, this.baseSeq, this.deleted, this.blob);
}

class PushResult {
  final String id;
  final bool ok;
  final int seq;

  /// On conflict: the server's current version.
  final RemoteChange? current;
  PushResult(this.id, this.ok, this.seq, this.current);
}

class PullResult {
  final List<RemoteChange> changes;
  final int cursor;
  final bool hasMore;
  PullResult(this.changes, this.cursor, this.hasMore);
}

class DeviceInfo {
  final String id, name, platform;
  final int createdAt;
  final int? lastSeenAt;
  final bool revoked, current;
  DeviceInfo(this.id, this.name, this.platform, this.createdAt,
      this.lastSeenAt, this.revoked, this.current);
}

class EnrollResult {
  final String deviceId, token, vaultId;
  EnrollResult(this.deviceId, this.token, this.vaultId);
}

class RemoteKeyslot {
  final int version;
  final Uint8List blob;
  RemoteKeyslot(this.version, this.blob);
}

/// What the sync engine needs from a server. Blobs are opaque ciphertext.
abstract class SyncApi {
  Future<PullResult> pull(int since, {int limit = 200});
  Future<List<PushResult>> push(List<PushItem> items);
  Future<RemoteKeyslot?> getKeyslot();

  /// Returns the new version. Throws [ApiException] with code
  /// `version_conflict` if [baseVersion] is stale.
  Future<int> putKeyslot(int baseVersion, Uint8List blob);
  Future<List<DeviceInfo>> devices();
  Future<void> revokeDevice(String id);
  Future<String> rotateToken();
  Future<({String code, int expiresAt})> createEnrollmentCode();

  /// Server clock in unix ms, as seen on the last response (0 if unknown).
  int get lastServerTime;
}

/// Decides whether a sync server URL may be used.
class UrlPolicy {
  /// Returns null if allowed, otherwise the reason it is refused.
  /// Plain HTTP is accepted only for loopback/private/LAN hosts and only
  /// when the user has explicitly allowed insecure LAN sync.
  static String? check(String url, {required bool allowInsecureLan}) {
    final Uri u;
    try {
      u = Uri.parse(url.trim());
    } catch (_) {
      return 'Not a valid URL.';
    }
    if (u.host.isEmpty) return 'Not a valid URL.';
    if (u.scheme == 'https') return null;
    if (u.scheme != 'http') return 'The URL must start with https://';
    if (!isLanHost(u.host)) {
      return 'Plain HTTP is only allowed for addresses on your own network. '
          'Use https:// for this server.';
    }
    if (!allowInsecureLan) {
      return 'This is an unencrypted LAN address. Turn on "Allow insecure '
          'LAN sync" to use it.';
    }
    return null;
  }

  static bool isLanHost(String host) {
    final h = host.toLowerCase();
    if (h == 'localhost') return true;
    if (h.endsWith('.local') || h.endsWith('.lan') || h.endsWith('.home.arpa')) {
      return true;
    }
    final ip = InternetAddress.tryParse(h);
    if (ip == null) return false;
    final b = ip.rawAddress;
    if (ip.type == InternetAddressType.IPv4) {
      return b[0] == 10 ||
          b[0] == 127 ||
          (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
          (b[0] == 192 && b[1] == 168) ||
          (b[0] == 169 && b[1] == 254);
    }
    return ip.isLoopback || (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80);
  }
}

/// HTTP implementation of [SyncApi] for the FastAPI server.
class HttpSyncApi implements SyncApi {
  final Uri base;
  String token;
  final http.Client _http;
  @override
  int lastServerTime = 0;

  HttpSyncApi(String baseUrl, this.token, {http.Client? client})
      : base = Uri.parse(baseUrl.trim().replaceAll(RegExp(r'/+$'), '')),
        _http = client ?? http.Client();

  /// An HTTP client that additionally trusts one certificate, identified by
  /// its SHA-256 fingerprint (hex), for self-signed homelab servers.
  static http.Client pinnedClient(String sha256Hex, List<int> Function(List<int>) sha256) {
    final want = sha256Hex.toLowerCase().replaceAll(RegExp('[^0-9a-f]'), '');
    final inner = HttpClient()
      ..badCertificateCallback = (cert, host, port) {
        final got = sha256(cert.der)
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join();
        return got == want;
      };
    return IOClient(inner);
  }

  static Future<EnrollResult> enroll(String baseUrl, String code,
      String deviceName, String platform,
      {http.Client? client}) async {
    final api = HttpSyncApi(baseUrl, '', client: client);
    final j = await api._send('POST', '/v1/enroll',
        body: {'code': code, 'device_name': deviceName, 'platform': platform},
        auth: false);
    return EnrollResult(j['device_id'] as String, j['token'] as String,
        j['vault_id'] as String);
  }

  Future<Map<String, dynamic>> _send(String method, String path,
      {Object? body, bool auth = true, Map<String, String>? query}) async {
    final uri = base.replace(
        path: '${base.path}$path', queryParameters: query);
    final req = http.Request(method, uri);
    if (auth) req.headers['authorization'] = 'Bearer $token';
    if (body != null) {
      req.headers['content-type'] = 'application/json';
      req.body = jsonEncode(body);
    }
    final http.Response res;
    try {
      res = await http.Response.fromStream(
          await _http.send(req).timeout(const Duration(seconds: 20)));
    } on ApiException {
      rethrow;
    } catch (e) {
      // Never include the request (it carries the token) in the message.
      throw OfflineException('Server unreachable (${e.runtimeType})');
    }
    final t = int.tryParse(res.headers['x-server-time'] ?? '');
    if (t != null) lastServerTime = t;
    Map<String, dynamic> j;
    try {
      j = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
    } catch (_) {
      j = {};
    }
    if (res.statusCode >= 200 && res.statusCode < 300) return j;
    final err = j['error'];
    if (err is Map) {
      throw ApiException(res.statusCode, '${err['code']}', '${err['message']}');
    }
    throw ApiException(res.statusCode, 'http_${res.statusCode}',
        'Unexpected response from server');
  }

  RemoteChange _change(Map j) => RemoteChange(j['id'] as String,
      j['seq'] as int, j['deleted'] as bool, base64.decode(j['blob'] as String));

  @override
  Future<PullResult> pull(int since, {int limit = 200}) async {
    final j = await _send('GET', '/v1/pull',
        query: {'since': '$since', 'limit': '$limit'});
    return PullResult([for (final c in j['changes'] as List) _change(c as Map)],
        j['cursor'] as int, j['has_more'] as bool);
  }

  @override
  Future<List<PushResult>> push(List<PushItem> items) async {
    final j = await _send('POST', '/v1/push', body: {
      'changes': [
        for (final i in items)
          {
            'id': i.id,
            'base_seq': i.baseSeq,
            'deleted': i.deleted,
            'blob': base64.encode(i.blob)
          }
      ]
    });
    return [
      for (final r in (j['results'] as List).cast<Map>())
        PushResult(r['id'] as String, r['status'] == 'ok', r['seq'] as int,
            r['status'] == 'ok' ? null : _change(r))
    ];
  }

  @override
  Future<RemoteKeyslot?> getKeyslot() async {
    try {
      final j = await _send('GET', '/v1/keyslot');
      return RemoteKeyslot(
          j['version'] as int, base64.decode(j['blob'] as String));
    } on ApiException catch (e) {
      if (e.status == 404) return null;
      rethrow;
    }
  }

  @override
  Future<int> putKeyslot(int baseVersion, Uint8List blob) async {
    final j = await _send('PUT', '/v1/keyslot',
        body: {'base_version': baseVersion, 'blob': base64.encode(blob)});
    return j['version'] as int;
  }

  @override
  Future<List<DeviceInfo>> devices() async {
    final j = await _send('GET', '/v1/devices');
    return [
      for (final d in (j['devices'] as List).cast<Map>())
        DeviceInfo(
            d['id'] as String,
            d['name'] as String,
            d['platform'] as String,
            d['created_at'] as int,
            d['last_seen_at'] as int?,
            d['revoked'] as bool,
            d['current'] as bool)
    ];
  }

  @override
  Future<void> revokeDevice(String id) => _send('DELETE', '/v1/devices/$id');

  @override
  Future<String> rotateToken() async {
    final j = await _send('POST', '/v1/devices/self/rotate-token');
    return token = j['token'] as String;
  }

  @override
  Future<({String code, int expiresAt})> createEnrollmentCode() async {
    final j = await _send('POST', '/v1/enrollment-codes');
    return (code: j['code'] as String, expiresAt: j['expires_at'] as int);
  }

  Future<Map<String, dynamic>> status() => _send('GET', '/v1/status');

  void close() => _http.close();
}
