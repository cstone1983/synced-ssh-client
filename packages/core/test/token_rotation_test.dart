import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sshsync_core/sshsync_core.dart';
import 'package:test/test.dart';

/// Just enough of the server's token handling: one device, its token hash,
/// and an empty pull. [dropNextReply] applies the next request, then loses
/// the reply.
class TokenServer {
  String tokenHash;
  bool dropNextReply = false;
  int rotations = 0;
  TokenServer(String token) : tokenHash = HttpSyncApi.tokenHash(token);

  late final client = MockClient((req) async {
    final bearer = (req.headers['authorization'] ?? '').replaceFirst('Bearer ', '');
    if (HttpSyncApi.tokenHash(bearer) != tokenHash) {
      return http.Response(
          jsonEncode({
            'error': {'code': 'unauthorized', 'message': 'missing or invalid token'}
          }),
          401);
    }
    final http.Response res;
    switch (req.url.path) {
      case '/v1/devices/self/rotate-token':
        final body = jsonDecode(req.body) as Map<String, dynamic>;
        tokenHash = body['token_hash'] as String;
        rotations++;
        res = http.Response(jsonEncode({'rotated': true}), 200);
      case '/v1/pull':
        res = http.Response(
            jsonEncode({'changes': [], 'cursor': 0, 'has_more': false}), 200);
      default:
        res = http.Response('{}', 404);
    }
    if (dropNextReply) {
      dropNextReply = false;
      throw http.ClientException('connection reset');
    }
    return res;
  });
}

void main() {
  late SodiumCrypto c;
  setUpAll(() async => c = await SodiumCrypto.load());

  test('new tokens look like the server\'s: 43 url-safe chars, all different', () {
    final seen = <String>{};
    for (var i = 0; i < 50; i++) {
      final t = HttpSyncApi.newToken();
      expect(t, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
      seen.add(t);
    }
    expect(seen, hasLength(50));
    expect(HttpSyncApi.tokenHash('abc'),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  test('rotation: the new token is saved as pending before it is sent', () async {
    final server = TokenServer('old');
    final saved = <(String, String?)>[];
    final api = HttpSyncApi('https://sync.test', 'old',
        client: server.client, saveTokens: (t, p) async {
      // When the server hears of the new token, it must already be saved.
      expect(server.rotations, saved.isEmpty ? 0 : 1);
      saved.add((t, p));
    });
    final next = await api.rotateToken();
    expect(saved.first.$1, 'old');
    expect(saved.first.$2, next);
    expect(saved.last, (next, null));
    expect(api.token, next);
    expect(api.pendingToken, isNull);
    expect(server.tokenHash, HttpSyncApi.tokenHash(next));
  });

  test('rotation: a lost reply does not lock the device out', () async {
    final server = TokenServer('old');
    String? savedToken = 'old', savedPending;
    Future<void> save(String t, String? p) async {
      savedToken = t;
      savedPending = p;
    }

    final api = HttpSyncApi('https://sync.test', 'old',
        client: server.client, saveTokens: save);
    server.dropNextReply = true;
    await expectLater(api.rotateToken(), throwsA(isA<OfflineException>()));
    expect(server.rotations, 1, reason: 'the server did rotate');
    expect(savedToken, 'old');
    expect(savedPending, isNotNull);
    final next = savedPending!;

    // The app restarts with what it saved; syncing still works and settles
    // on the new token.
    final store = Store.memory(Vault(c)..unlockWithKey(c.randomBytes(32)));
    final api2 = HttpSyncApi('https://sync.test', savedToken!,
        client: server.client, pendingToken: savedPending, saveTokens: save);
    final engine = SyncEngine(store, api2);
    expect(await engine.syncOnce(), isTrue);
    expect(api2.token, next);
    expect(api2.pendingToken, isNull);
    expect(savedToken, next);
    expect(savedPending, isNull);
  });

  test('rotation: retrying after a lost reply finishes the same rotation', () async {
    final server = TokenServer('old');
    final api = HttpSyncApi('https://sync.test', 'old', client: server.client);
    server.dropNextReply = true;
    await expectLater(api.rotateToken(), throwsA(isA<OfflineException>()));
    final pending = api.pendingToken!;
    final next = await api.rotateToken();
    expect(next, pending, reason: 'a second fresh token would lock the device out');
    expect(server.tokenHash, HttpSyncApi.tokenHash(next));
    expect(await api.pull(0), isA<PullResult>());
  });

  test('rotation that never reached the server keeps the old token working', () async {
    final server = TokenServer('old');
    final api = HttpSyncApi('https://sync.test', 'old',
        client: server.client, pendingToken: 'never-sent');
    expect(await api.pull(0), isA<PullResult>());
    expect(api.token, 'old');

    // Both refused: the original error comes through.
    server.tokenHash = HttpSyncApi.tokenHash('someone-else');
    await expectLater(
        api.pull(0),
        throwsA(isA<ApiException>()
            .having((e) => e.code, 'code', 'unauthorized')));
    expect(api.token, 'old');
  });
}
