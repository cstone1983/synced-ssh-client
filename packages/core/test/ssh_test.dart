@Tags(['ssh'])
library;

// Real connections against a local OpenSSH server. Needs root and sshd;
// skipped otherwise.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:sshsync_core/sshsync_core.dart';
import 'package:test/test.dart';

const user = 'sshsynctest';
const pass = 'Pw-12345-test';

class Prompts implements SshPrompts {
  bool acceptHostKey = true;
  String? passwordAnswer;
  final hostKeyQuestions = <HostKeyQuestion>[];
  final passwordCalls = <bool>[];

  @override
  Future<bool> confirmHostKey(HostKeyQuestion q) async {
    hostKeyQuestions.add(q);
    return acceptHostKey;
  }

  @override
  Future<String?> password(String label, {required bool retry}) async {
    passwordCalls.add(retry);
    final p = passwordAnswer;
    passwordAnswer = null;
    return p;
  }

  @override
  Future<List<String>?> keyboardInteractive(String label, String instruction,
          List<InteractivePrompt> prompts) async =>
      null;
}

bool get canRun =>
    Platform.isLinux &&
    File('/usr/sbin/sshd').existsSync() &&
    Process.runSync('id', ['-u']).stdout.toString().trim() == '0';

void main() {
  if (!canRun) {
    test('ssh tests', () {}, skip: 'needs root and /usr/sbin/sshd');
    return;
  }

  late SodiumCrypto c;
  late Directory tmp;
  late Store store;
  late Prompts prompts;
  late SessionManager mgr;
  Process? sshd;
  const port = 22922;

  Future<void> startSshd({bool newHostKey = false}) async {
    sshd?.kill();
    await sshd?.exitCode;
    final key = '${tmp.path}/hostkey';
    if (newHostKey || !File(key).existsSync()) {
      for (final f in [key, '$key.pub']) {
        if (File(f).existsSync()) File(f).deleteSync();
      }
      Process.runSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]);
    }
    File('${tmp.path}/sshd_config').writeAsStringSync('''
Port $port
ListenAddress 127.0.0.1
HostKey $key
PidFile ${tmp.path}/sshd.pid
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
AllowUsers $user
AllowTcpForwarding yes
''');
    Directory('/run/sshd').createSync(recursive: true);
    sshd = await Process.start(
        '/usr/sbin/sshd', ['-D', '-e', '-f', '${tmp.path}/sshd_config']);
    sshd!.stderr.drain<void>();
    sshd!.stdout.drain<void>();
    for (var i = 0; i < 50; i++) {
      try {
        (await Socket.connect('127.0.0.1', port)).destroy();
        return;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('sshd did not start');
  }

  setUpAll(() async {
    c = await SodiumCrypto.load();
    tmp = Directory.systemTemp.createTempSync('sshsync-ssh');
    Process.runSync('userdel', ['-r', user]);
    final add = Process.runSync('useradd', ['-m', '-s', '/bin/bash', user]);
    expect(add.exitCode, 0, reason: '${add.stderr}');
    final p = await Process.start('chpasswd', []);
    p.stdin.writeln('$user:$pass');
    await p.stdin.close();
    expect(await p.exitCode, 0);
    await startSshd();
  });

  tearDownAll(() async {
    sshd?.kill();
    Process.runSync('userdel', ['-r', user]);
    tmp.deleteSync(recursive: true);
  });

  setUp(() async {
    final v = Vault(c);
    await v.create('p', params: KdfParams.fast);
    store = Store.memory(v);
    prompts = Prompts();
    mgr = SessionManager(store, prompts);
  });

  tearDown(() => mgr.closeAll());

  ConnectSpec spec(
          {String? password = pass,
          String? key,
          String order = AuthOrder.keyThenPassword,
          int p = port,
          ConnectSpec? jump}) =>
      ConnectSpec(
          label: 'test',
          host: '127.0.0.1',
          port: p,
          username: user,
          password: password,
          privateKeyPem: key,
          authOrder: order,
          jump: jump);

  Future<String> runShell(TerminalSession s, String marker, String cmd) async {
    final out = StringBuffer();
    s.onData = out.write;
    for (var i = 0; i < 100 && s.state == SessionState.connecting; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(s.state, SessionState.connected, reason: s.error);
    s.write('$cmd\n');
    for (var i = 0; i < 100 && !out.toString().contains(marker); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    return out.toString();
  }

  test('password login, shell I/O, resize, host state recorded', () async {
    final host = store.put('host', {'nickname': 'local', 'hostname': '127.0.0.1', 'port': port,
      'credential_id': store.put('credential', {'label': 'c', 'username': user, 'password': pass}),
      'startup_command': 'echo started-\$((40+2))'});
    final s = mgr.openHost(store.get(host)!);
    s.resize(100, 30);
    final out = await runShell(s, 'cols=100', 'echo cols=\$(tput cols 2>/dev/null || stty size | cut -d" " -f2)');
    expect(out, contains('started-42'));
    expect(out, contains('cols=100'));
    expect(mgr.hostState(host)['status'], 'connected');
    expect(mgr.hostState(host)['last_connected_at'], isA<int>());
    expect(mgr.activeCount, 1);
    s.disconnect();
    expect(s.state, SessionState.disconnected);
    expect(mgr.activeCount, 0);
  });

  test('trust on first use, remembered, and a changed key is blocked', () async {
    final conn = await sshConnect(spec(), mgr.knownHosts, prompts);
    conn.close();
    expect(prompts.hostKeyQuestions, hasLength(1));
    expect(prompts.hostKeyQuestions.single.changed, isFalse);
    expect(prompts.hostKeyQuestions.single.keyType, 'ssh-ed25519');
    final fp = prompts.hostKeyQuestions.single.fingerprint;
    final real = Process.runSync('ssh-keygen', ['-lf', '${tmp.path}/hostkey.pub']).stdout.toString().split(' ')[1];
    expect(fp, real, reason: 'same fingerprint ssh-keygen shows');
    expect(store.list('known_host').single.str('fingerprint'), fp);

    (await sshConnect(spec(), mgr.knownHosts, prompts)).close();
    expect(prompts.hostKeyQuestions, hasLength(1), reason: 'not asked again');

    await startSshd(newHostKey: true);
    prompts.acceptHostKey = false;
    await expectLater(sshConnect(spec(), mgr.knownHosts, prompts),
        throwsA(isA<SshFailure>().having((e) => e.kind, 'kind', SshFailureKind.hostKey)));
    expect(prompts.hostKeyQuestions.last.changed, isTrue);
    expect(prompts.hostKeyQuestions.last.previousFingerprint, fp);
    expect(store.list('known_host').single.str('fingerprint'), fp, reason: 'old key kept');

    prompts.acceptHostKey = true;
    (await sshConnect(spec(), mgr.knownHosts, prompts)).close();
    expect(store.list('known_host').single.str('fingerprint'), isNot(fp));
  });

  test('install key, key only, key then password fallback, password only', () async {
    final key = Keys.generateEd25519(c, comment: 'sshsync-test');
    final conn = await sshConnect(spec(), mgr.knownHosts, prompts);
    await installPublicKey(conn.client, key.publicLine);
    await installPublicKey(conn.client, key.publicLine);
    conn.close();
    final auth = File('/home/$user/.ssh/authorized_keys');
    expect(auth.readAsLinesSync().where((l) => l == key.publicLine), hasLength(1), reason: 'not duplicated');
    expect(Process.runSync('stat', ['-c', '%a', auth.path]).stdout.toString().trim(), '600');
    expect(Process.runSync('stat', ['-c', '%a', '/home/$user/.ssh']).stdout.toString().trim(), '700');

    (await sshConnect(spec(password: null, key: key.privatePem, order: AuthOrder.keyOnly), mgr.knownHosts, prompts)).close();
    expect(prompts.passwordCalls, isEmpty);

    final other = Keys.generateEd25519(c);
    (await sshConnect(spec(key: other.privatePem), mgr.knownHosts, prompts)).close();

    await expectLater(sshConnect(spec(key: other.privatePem, order: AuthOrder.keyOnly), mgr.knownHosts, prompts),
        throwsA(isA<SshFailure>().having((e) => e.kind, 'kind', SshFailureKind.auth)));

    (await sshConnect(spec(key: other.privatePem, order: AuthOrder.passwordOnly), mgr.knownHosts, prompts)).close();

    await expectLater(sshConnect(spec(password: null, order: AuthOrder.keyOnly), mgr.knownHosts, prompts),
        throwsA(isA<SshFailure>().having((e) => e.message, 'message', contains('key only'))));

    await expectLater(installPublicKey(conn.client, "x'; rm -rf ~; '"), throwsA(isA<SshFailure>()));
  });

  test('prompted password: asked, retried on a wrong one, cancel aborts', () async {
    prompts.passwordAnswer = pass;
    (await sshConnect(spec(password: null), mgr.knownHosts, prompts)).close();
    expect(prompts.passwordCalls, [false]);

    prompts.passwordCalls.clear();
    await expectLater(sshConnect(spec(password: 'wrong'), mgr.knownHosts, prompts),
        throwsA(isA<SshFailure>().having((e) => e.kind, 'kind', SshFailureKind.cancelled)));
    expect(prompts.passwordCalls, [true], reason: 'asked again after the stored one failed');

    prompts.passwordCalls.clear();
    prompts.passwordAnswer = pass;
    (await sshConnect(spec(password: 'wrong'), mgr.knownHosts, prompts)).close();
    expect(prompts.passwordCalls, [true], reason: 'a corrected password connects');
  });

  test('unreachable host reports clearly and does not retry auth failures', () async {
    await expectLater(sshConnect(spec(p: 22923), mgr.knownHosts, prompts),
        throwsA(isA<SshFailure>().having((e) => e.kind, 'kind', SshFailureKind.unreachable)));
    final s = mgr.open(spec(p: 22923), autoReconnect: true);
    for (var i = 0; i < 50 && s.state == SessionState.connecting; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(s.state, SessionState.disconnected);
    expect(s.reconnectIn, 2, reason: 'unreachable is retried');
    s.cancelReconnect();
    expect(s.reconnectIn, isNull);
  });

  test('jump host: connects through another SSH hop', () async {
    final conn = await sshConnect(spec(jump: spec()), mgr.knownHosts, prompts);
    final out = utf8.decode(await conn.client.run('echo via-jump'));
    expect(out.trim(), 'via-jump');
    conn.close();
  });

  test('local, remote and dynamic forwards', () async {
    final echo = await ServerSocket.bind('127.0.0.1', 0);
    echo.listen((s) => s.listen((d) => s.add(utf8.encode('echo:${utf8.decode(d)}'))));
    addTearDown(echo.close);

    final s = mgr.open(spec(), forwards: [
      ForwardSpec('L', '127.0.0.1', 22931, '127.0.0.1', echo.port),
      ForwardSpec('R', '127.0.0.1', 22932, '127.0.0.1', echo.port),
      const ForwardSpec('D', '127.0.0.1', 22933),
      ForwardSpec('L', '127.0.0.1', echo.port, '127.0.0.1', 1),
    ]);
    for (var i = 0; i < 100 && (s.forwards.length < 4 || s.forwards.any((f) => !f.active && f.error == null)); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(s.state, SessionState.connected, reason: s.error);
    expect(s.forwards.take(3).map((f) => f.active), [true, true, true], reason: s.forwards.map((f) => f.error).join(','));
    expect(s.forwards[3].active, isFalse);
    expect(s.forwards[3].error, contains('not available'));

    Future<String> roundTrip(int p, String msg) async {
      final sock = await Socket.connect('127.0.0.1', p);
      sock.add(utf8.encode(msg));
      final reply = utf8.decode(await sock.first.timeout(const Duration(seconds: 10)));
      sock.destroy();
      return reply;
    }

    expect(await roundTrip(22931, 'L'), 'echo:L');
    expect(await roundTrip(22932, 'R'), 'echo:R');

    // SOCKS5 CONNECT through the dynamic forward.
    final socks = await Socket.connect('127.0.0.1', 22933);
    final it = StreamIterator(socks);
    socks.add([5, 1, 0]);
    await it.moveNext();
    expect(it.current, [5, 0]);
    socks.add([5, 1, 0, 1, 127, 0, 0, 1, echo.port >> 8, echo.port & 0xff]);
    await it.moveNext();
    expect(it.current[1], 0, reason: 'SOCKS connect succeeded');
    socks.add(utf8.encode('D'));
    await it.moveNext();
    expect(utf8.decode(it.current), 'echo:D');
    socks.destroy();

    s.disconnect();
    await expectLater(Socket.connect('127.0.0.1', 22931), throwsA(isA<SocketException>()));
  });
}
