import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:pointycastle/digests/sha256.dart';

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

  /// Replace this device's token; returns the new one.
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

/// Persists this device's tokens. [pending] is a new token that was sent to
/// the server but not yet confirmed; null once it is settled.
typedef TokenSaver = Future<void> Function(String token, String? pending);

/// HTTP implementation of [SyncApi] for the FastAPI server.
class HttpSyncApi implements SyncApi {
  final Uri base;
  String token;

  /// A new token sent in a rotation whose reply never arrived. If the
  /// current token is refused, this one is tried and adopted when it works.
  String? pendingToken;
  final TokenSaver? saveTokens;
  final http.Client _http;
  @override
  int lastServerTime = 0;

  HttpSyncApi(String baseUrl, this.token,
      {http.Client? client, this.pendingToken, this.saveTokens})
      : base = Uri.parse(baseUrl.trim().replaceAll(RegExp(r'/+$'), '')),
        _http = client ?? http.Client();

  /// 256 random bits, URL-safe base64 without padding (43 characters), the
  /// same shape as the server's own tokens.
  static String newToken() {
    final r = Random.secure();
    final bytes = Uint8List.fromList(List.generate(32, (_) => r.nextInt(256)));
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  static String tokenHash(String token) => SHA256Digest()
      .process(Uint8List.fromList(utf8.encode(token)))
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  Future<void> _adopt(String t) async {
    token = t;
    pendingToken = null;
    await saveTokens?.call(t, null);
  }

  /// An HTTP client that additionally trusts one certificate, identified by
  /// its SHA-256 fingerprint (hex), for self-signed homelab servers.
  static http.Client pinnedClient(String sha256Hex) {
    final want = sha256Hex.toLowerCase().replaceAll(RegExp('[^0-9a-f]'), '');
    final inner = HttpClient()
      ..badCertificateCallback = (cert, host, port) {
        final got = SHA256Digest()
            .process(Uint8List.fromList(cert.der))
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

  /// Ask the server to send a one-time enrollment code to its owner (by
  /// Telegram, through the server's webhook). The code is never returned
  /// here. Throws [ApiException] `not_available` when the server has no
  /// webhook set up, `rate_limited`, or `notify_failed`.
  static Future<void> requestEnrollmentCode(
      String baseUrl, String deviceName, String platform,
      {http.Client? client}) async {
    final api = HttpSyncApi(baseUrl, '', client: client);
    try {
      await api._send('POST', '/v1/enrollment-codes/request',
          body: {'device_name': deviceName, 'platform': platform}, auth: false);
    } finally {
      if (client == null) api.close();
    }
  }

  Future<Map<String, dynamic>> _send(String method, String path,
      {Object? body, bool auth = true, Map<String, String>? query}) async {
    final res = await _request(method, path, body, auth ? token : null, query);
    final pending = pendingToken;
    if (auth &&
        pending != null &&
        pending != token &&
        res.status == 401 &&
        res.code == 'unauthorized') {
      // A rotation went through but its reply was lost: use the new token.
      final retry = await _request(method, path, body, pending, query);
      if (retry.status >= 200 && retry.status < 300) await _adopt(pending);
      return retry.unwrap();
    }
    return res.unwrap();
  }

  Future<_Reply> _request(String method, String path, Object? body,
      String? bearer, Map<String, String>? query) async {
    final uri = base.replace(
        path: '${base.path}$path', queryParameters: query);
    final req = http.Request(method, uri);
    if (bearer != null) req.headers['authorization'] = 'Bearer $bearer';
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
    return _Reply(res.statusCode, j);
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

  /// The new token is made here and saved as pending before the server
  /// hears of it, so a lost reply can never leave this device without a
  /// working token: the next request falls back to the pending one. A
  /// pending token left by an earlier, unconfirmed rotation is reused, so a
  /// retry finishes that rotation instead of starting one the server
  /// never saw.
  @override
  Future<String> rotateToken() async {
    final next = pendingToken ?? newToken();
    if (pendingToken == null) {
      pendingToken = next;
      await saveTokens?.call(token, next);
    }
    await _send('POST', '/v1/devices/self/rotate-token',
        body: {'token_hash': tokenHash(next)});
    if (token != next) await _adopt(next);
    return token;
  }

  @override
  Future<({String code, int expiresAt})> createEnrollmentCode() async {
    final j = await _send('POST', '/v1/enrollment-codes');
    return (code: j['code'] as String, expiresAt: j['expires_at'] as int);
  }

  Future<Map<String, dynamic>> status() => _send('GET', '/v1/status');

  void close() => _http.close();
}

class _Reply {
  final int status;
  final Map<String, dynamic> json;
  _Reply(this.status, this.json);

  String? get code {
    final err = json['error'];
    return err is Map ? '${err['code']}' : null;
  }

  Map<String, dynamic> unwrap() {
    if (status >= 200 && status < 300) return json;
    final err = json['error'];
    if (err is Map) {
      throw ApiException(status, '${err['code']}', '${err['message']}');
    }
    throw ApiException(status, 'http_$status', 'Unexpected response from server');
  }
}
