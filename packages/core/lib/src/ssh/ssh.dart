import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';

import '../store/schema.dart';
import '../store/store.dart';

// ---------------------------------------------------------------- specs

class ForwardSpec {
  /// 'L' local, 'R' remote, 'D' dynamic SOCKS.
  final String kind;
  final String bindHost;
  final int bindPort;
  final String destHost;
  final int destPort;
  const ForwardSpec(this.kind, this.bindHost, this.bindPort,
      [this.destHost = '', this.destPort = 0]);

  factory ForwardSpec.fromJson(Map j) => ForwardSpec(
      j['kind'] as String,
      (j['bind_host'] as String?) ?? '127.0.0.1',
      (j['bind_port'] as num).toInt(),
      (j['dest_host'] as String?) ?? '',
      (j['dest_port'] as num?)?.toInt() ?? 0);

  Map<String, dynamic> toJson() => {
        'kind': kind,
        'bind_host': bindHost,
        'bind_port': bindPort,
        'dest_host': destHost,
        'dest_port': destPort,
      };

  String get label => kind == 'D'
      ? 'SOCKS $bindHost:$bindPort'
      : '$kind $bindHost:$bindPort → $destHost:$destPort';
}

/// Everything needed to open one connection, resolved to plain values.
class ConnectSpec {
  final String label;
  final String host;
  final int port;
  final String username;
  final String authOrder;
  final String? password;
  final String? privateKeyPem;
  final int keepaliveSeconds;
  final bool legacyAlgorithms;
  final ConnectSpec? jump;

  const ConnectSpec({
    required this.label,
    required this.host,
    this.port = 22,
    required this.username,
    this.authOrder = AuthOrder.keyThenPassword,
    this.password,
    this.privateKeyPem,
    this.keepaliveSeconds = 30,
    this.legacyAlgorithms = false,
    this.jump,
  });

  /// Builds a spec from a saved host, following its credential and jump
  /// host. The vault must be unlocked for secrets to be present.
  static ConnectSpec fromHost(Store store, Rec host,
      {int defaultKeepalive = 30, int depth = 0}) {
    final cred = store.get(host.get<String>('credential_id'));
    final jumpRec =
        depth < 1 ? store.get(host.get<String>('jump_host_id')) : null;
    final ka = host.integer('keepalive');
    return ConnectSpec(
      label: host.str('nickname', host.str('hostname')),
      host: host.str('hostname'),
      port: host.integer('port', 22),
      username: cred?.str('username') ?? '',
      authOrder: host.str('auth_order', AuthOrder.keyThenPassword),
      password: cred?.get<String>('password'),
      privateKeyPem: cred?.get<String>('private_key'),
      keepaliveSeconds: ka > 0 ? ka : defaultKeepalive,
      legacyAlgorithms: host.flag('legacy_algorithms'),
      jump: jumpRec == null
          ? null
          : fromHost(store, jumpRec,
              defaultKeepalive: defaultKeepalive, depth: depth + 1),
    );
  }
}

// ---------------------------------------------------------------- prompts

class HostKeyQuestion {
  final String host;
  final int port;
  final String keyType;
  final String fingerprint;

  /// Null on first contact. Non-null means the key CHANGED: possible
  /// man-in-the-middle, and the default answer must be "no".
  final String? previousFingerprint;

  /// Key type of [previousFingerprint], when known.
  final String? previousKeyType;
  HostKeyQuestion(this.host, this.port, this.keyType, this.fingerprint,
      this.previousFingerprint,
      [this.previousKeyType]);
  bool get changed => previousFingerprint != null;
}

class InteractivePrompt {
  final String text;
  final bool echo;
  InteractivePrompt(this.text, this.echo);
}

/// Questions the connection may need to ask the person at the keyboard.
abstract class SshPrompts {
  Future<bool> confirmHostKey(HostKeyQuestion q);

  /// Return null to cancel.
  Future<String?> password(String label, {required bool retry});
  Future<List<String>?> keyboardInteractive(
      String label, String instruction, List<InteractivePrompt> prompts);
}

// ---------------------------------------------------------------- known hosts

/// Trust-on-first-use host keys, stored as synced records so a host trusted
/// on one device is trusted on the others.
///
/// A host is identified by host and port only. Every trusted key for it
/// counts, whatever its type, so a server that suddenly presents a key of
/// another type gets the "key changed" warning, not a first-contact prompt.
class KnownHosts {
  final Store store;
  KnownHosts(this.store);

  static const _rsa = {'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'};

  /// The kind of key behind a host key algorithm name. The three RSA
  /// signature names all use the same RSA key.
  static String keyFamily(String type) =>
      _rsa.contains(type) ? 'ssh-rsa' : type;

  // Keyed by fingerprint, so two devices trusting two different keys for one
  // host never write the same record.
  String _id(String host, int port, String fingerprint) => store.vault
      .deterministicId('known_host|${host.toLowerCase()}|$port|$fingerprint');

  /// Every trusted key for [host]:[port]. Entries written by older versions
  /// (one per algorithm name, with a trust time) are read the same way and
  /// come first, newest first.
  List<Rec> trustedKeys(String host, int port) {
    final h = host.toLowerCase();
    return store
        .list(RecordType.knownHost)
        .where((r) =>
            r.str('host').toLowerCase() == h &&
            r.integer('port', 22) == port &&
            r.str('fingerprint').isNotEmpty)
        .toList()
      ..sort((a, b) =>
          b.integer('trusted_at').compareTo(a.integer('trusted_at')));
  }

  /// Whether [fingerprint] is one of the trusted keys for [host]:[port].
  bool isTrusted(String host, int port, String fingerprint) =>
      trustedKeys(host, port).any((r) => r.str('fingerprint') == fingerprint);

  /// Key families already trusted for [host]:[port].
  Set<String> trustedFamilies(String host, int port) => {
        for (final r in trustedKeys(host, port))
          if (r.str('key_type').isNotEmpty) keyFamily(r.str('key_type'))
      };

  /// Trusts [fingerprint] for [host]:[port] and drops every other key
  /// trusted for it: accepting a changed key replaces the old one.
  void trust(String host, int port, String type, String fingerprint) {
    var id = _id(host, port, fingerprint);
    for (final old in trustedKeys(host, port)) {
      if (old.id != id) store.delete(old.id);
    }
    // A key that was replaced earlier left a tombstone under this id, and
    // tombstones are final. Trusting that key again needs a fresh record.
    if (store.syncRow(id)?.state.isDeleted ?? false) {
      id = store.vault.randomId();
    }
    // Only values that are the same on every device that trusts this key,
    // so two devices trusting it offline merge without a conflict note.
    store.put(RecordType.knownHost, id: id, {
      'host': host.toLowerCase(),
      'port': port,
      'key_type': keyFamily(type),
      'fingerprint': fingerprint,
    });
  }
}

// ---------------------------------------------------------------- connect

enum SshFailureKind { unreachable, hostKey, auth, cancelled, disconnected, other }

class SshFailure implements Exception {
  final SshFailureKind kind;
  final String message;
  SshFailure(this.kind, this.message);
  @override
  String toString() => message;
}

class SshConnection {
  final SSHClient client;
  final SshConnection? via;
  SshConnection(this.client, this.via);

  Future<void> get done => client.done;

  void close() {
    client.close();
    via?.close();
  }
}

/// Algorithm lists for one connection. Host key algorithms whose key type is
/// already trusted for this host go first, as OpenSSH does, so a server that
/// adds a new key type keeps presenting the one we know instead of raising a
/// false "key changed" alarm.
SSHAlgorithms _algorithms(bool legacy,
    {Set<String> trustedFamilies = const {}}) {
  const d = SSHAlgorithms();
  bool known(SSHHostkeyType t) =>
      trustedFamilies.contains(KnownHosts.keyFamily(t.name));
  final base = [...d.hostkey, if (legacy) SSHHostkeyType.rsaSha1];
  final hostkey = [...base.where(known), ...base.where((t) => !known(t))];
  if (!legacy) {
    return SSHAlgorithms(
        kex: d.kex, hostkey: hostkey, cipher: d.cipher, mac: d.mac);
  }
  return SSHAlgorithms(
    kex: [...d.kex, SSHKexType.dhGexSha1, SSHKexType.dh14Sha1, SSHKexType.dh1Sha1],
    hostkey: hostkey,
    cipher: [
      ...d.cipher,
      SSHCipherType.aes256cbc,
      SSHCipherType.aes192cbc,
      SSHCipherType.aes128cbc
    ],
    mac: d.mac,
  );
}

/// Opens an authenticated connection, through the jump host if one is set.
/// Host keys are verified on every hop. Throws [SshFailure].
Future<SshConnection> sshConnect(
    ConnectSpec spec, KnownHosts known, SshPrompts prompts) async {
  // The SSH library offers a password once per connection. If it is refused
  // and passwords are allowed, ask for another and connect again.
  String? override;
  for (var attempt = 0;; attempt++) {
    try {
      return await _connectOnce(spec, known, prompts, override, attempt > 0);
    } on SshFailure catch (e) {
      final canAsk = e.kind == SshFailureKind.auth &&
          spec.authOrder != AuthOrder.keyOnly &&
          spec.username.isNotEmpty &&
          attempt < 2;
      if (!canAsk) rethrow;
      override = await prompts.password(spec.label, retry: true);
      if (override == null) {
        throw SshFailure(SshFailureKind.cancelled, 'Cancelled.');
      }
    }
  }
}

Future<SshConnection> _connectOnce(ConnectSpec spec, KnownHosts known,
    SshPrompts prompts, String? passwordOverride, bool isRetry) async {
  SshConnection? via;
  try {
    final SSHSocket socket;
    if (spec.jump != null) {
      via = await sshConnect(spec.jump!, known, prompts);
      try {
        socket = await via.client.forwardLocal(spec.host, spec.port);
      } catch (_) {
        throw SshFailure(SshFailureKind.unreachable,
            '${spec.jump!.label} could not reach ${spec.host}:${spec.port}.');
      }
    } else {
      try {
        socket = await SSHSocket.connect(spec.host, spec.port,
            timeout: const Duration(seconds: 15));
      } catch (e) {
        throw SshFailure(SshFailureKind.unreachable,
            'Could not reach ${spec.host}:${spec.port}.');
      }
    }

    if (spec.username.isEmpty) {
      throw SshFailure(SshFailureKind.auth, 'No username set for ${spec.label}.');
    }
    final wantsKey = spec.authOrder != AuthOrder.passwordOnly;
    final wantsPassword = spec.authOrder != AuthOrder.keyOnly;
    List<SSHKeyPair>? identities;
    if (wantsKey && (spec.privateKeyPem?.isNotEmpty ?? false)) {
      try {
        identities = SSHKeyPair.fromPem(spec.privateKeyPem!);
      } catch (_) {
        throw SshFailure(
            SshFailureKind.auth, 'The stored private key could not be read.');
      }
    }
    if (!wantsPassword && identities == null) {
      throw SshFailure(SshFailureKind.auth,
          '${spec.label} is set to "key only" but its credential has no key.');
    }

    String? hostKeyProblem;
    var cancelled = false;
    var storedPasswordUsed = false;
    var passwordAsked = false;

    Future<String?> nextPassword() async {
      final stored = passwordOverride ?? spec.password;
      if (!storedPasswordUsed && (stored?.isNotEmpty ?? false)) {
        storedPasswordUsed = true;
        return stored;
      }
      if (storedPasswordUsed || passwordAsked) return null;
      final p = await prompts.password(spec.label, retry: isRetry);
      passwordAsked = true;
      if (p == null) cancelled = true;
      return p;
    }

    final client = SSHClient(
      socket,
      username: spec.username,
      algorithms: _algorithms(spec.legacyAlgorithms,
          trustedFamilies: known.trustedFamilies(spec.host, spec.port)),
      identities: identities,
      keepAliveInterval: spec.keepaliveSeconds > 0
          ? Duration(seconds: spec.keepaliveSeconds)
          : null,
      onVerifyHostKey: (type, fingerprintBytes) async {
        var fp = utf8.decode(fingerprintBytes, allowMalformed: true);
        if (!fp.startsWith('SHA256:')) fp = 'SHA256:$fp';
        final trusted = known.trustedKeys(spec.host, spec.port);
        if (trusted.any((r) => r.str('fingerprint') == fp)) return true;
        // Any trusted key at all means this is a change. Show the trusted
        // key of the same kind if there is one, else the newest.
        final family = KnownHosts.keyFamily(type);
        final previous = trusted.isEmpty
            ? null
            : trusted.firstWhere(
                (r) => KnownHosts.keyFamily(r.str('key_type')) == family,
                orElse: () => trusted.first);
        final ok = await prompts.confirmHostKey(HostKeyQuestion(
            spec.host,
            spec.port,
            type,
            fp,
            previous?.str('fingerprint'),
            previous?.get<String>('key_type')));
        if (ok) {
          known.trust(spec.host, spec.port, type, fp);
        } else {
          hostKeyProblem = previous == null
              ? 'Host key was not trusted.'
              : 'Host key changed and was not accepted.';
        }
        return ok;
      },
      onPasswordRequest: wantsPassword ? nextPassword : null,
      onUserInfoRequest: wantsPassword
          ? (req) async {
              if (req.prompts.isEmpty) return <String>[];
              // A single hidden prompt is almost always "Password:".
              if (req.prompts.length == 1 && !req.prompts.first.echo) {
                final p = await nextPassword();
                return p == null ? null : [p];
              }
              final answers = await prompts.keyboardInteractive(
                  spec.label, req.instruction, [
                for (final p in req.prompts) InteractivePrompt(p.promptText, p.echo)
              ]);
              if (answers == null) cancelled = true;
              return answers;
            }
          : null,
    );

    try {
      await client.authenticated;
    } catch (e) {
      client.close();
      if (hostKeyProblem != null) {
        throw SshFailure(SshFailureKind.hostKey, hostKeyProblem!);
      }
      if (cancelled) throw SshFailure(SshFailureKind.cancelled, 'Cancelled.');
      if (e is SSHAuthFailError || e is SSHAuthAbortError) {
        throw SshFailure(SshFailureKind.auth,
            'Authentication failed for ${spec.username}@${spec.host}.');
      }
      if (e is SSHDisconnectError) {
        throw SshFailure(SshFailureKind.disconnected,
            'Server closed the connection: ${e.message}');
      }
      throw SshFailure(SshFailureKind.other,
          'Connection to ${spec.host} failed (${e.runtimeType}).');
    }
    return SshConnection(client, via);
  } catch (_) {
    via?.close();
    rethrow;
  }
}

// ---------------------------------------------------------------- install key

final _safeKeyLine = RegExp(r'^[A-Za-z0-9@._+/=:, -]+$');

/// Like ssh-copy-id: appends [publicLine] to ~/.ssh/authorized_keys with
/// correct permissions, unless it is already there.
Future<void> installPublicKey(SSHClient client, String publicLine) async {
  final line = publicLine.trim();
  if (!_safeKeyLine.hasMatch(line) || !line.contains(' ')) {
    throw SshFailure(SshFailureKind.other, 'Public key has unexpected characters.');
  }
  final cmd = "umask 077; mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
      "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
      "{ grep -qxF '$line' ~/.ssh/authorized_keys || "
      "printf '%s\\n' '$line' >> ~/.ssh/authorized_keys; }";
  final s = await client.execute(cmd);
  await s.stdout.drain<void>();
  await s.done;
  if (s.exitCode != 0) {
    throw SshFailure(SshFailureKind.other,
        'The server refused to update authorized_keys (exit ${s.exitCode}).');
  }
}

// ---------------------------------------------------------------- forwards

class ForwardStatus {
  final ForwardSpec spec;
  bool active = false;
  String? error;
  int connections = 0;
  ForwardStatus(this.spec);
}

class _Forwards {
  final SSHClient client;
  final void Function() changed;
  final statuses = <ForwardStatus>[];
  final _closers = <FutureOr<void> Function()>[];
  _Forwards(this.client, this.changed);

  Future<void> start(List<ForwardSpec> specs) async {
    for (final spec in specs) {
      final st = ForwardStatus(spec);
      statuses.add(st);
      try {
        switch (spec.kind) {
          case 'L':
            final server = await ServerSocket.bind(spec.bindHost, spec.bindPort);
            _closers.add(server.close);
            server.listen((sock) async {
              try {
                final ch = await client.forwardLocal(spec.destHost, spec.destPort);
                _pipe(st, sock, ch);
              } catch (_) {
                sock.destroy();
              }
            });
          case 'R':
            final fwd = await client.forwardRemote(
                host: spec.bindHost, port: spec.bindPort);
            if (fwd == null) throw 'the server refused the remote forward';
            _closers.add(fwd.close);
            fwd.connections.listen((ch) async {
              try {
                final sock = await Socket.connect(spec.destHost, spec.destPort,
                    timeout: const Duration(seconds: 10));
                _pipe(st, sock, ch);
              } catch (_) {
                ch.destroy();
              }
            });
          case 'D':
            final d = await client.forwardDynamic(
                bindHost: spec.bindHost, bindPort: spec.bindPort);
            _closers.add(d.close);
          default:
            throw 'unknown forward type';
        }
        st.active = true;
      } catch (e) {
        st.error = e is SocketException
            ? 'port ${spec.bindPort} is not available'
            : (e is String ? e : 'could not start (${e.runtimeType})');
      }
      changed();
    }
  }

  void _pipe(ForwardStatus st, Socket sock, SSHForwardChannel ch) {
    st.connections++;
    changed();
    var open = true;
    void end() {
      if (!open) return;
      open = false;
      st.connections--;
      sock.destroy();
      ch.destroy();
      changed();
    }

    ch.stream.listen(sock.add, onDone: end, onError: (_) => end());
    sock.listen(ch.sink.add, onDone: end, onError: (_) => end());
  }

  void stop() {
    // Closing a remote forward sends a cancel request whose reply never
    // comes once the client is closed; keep that error contained.
    runZonedGuarded(() {
      for (final c in _closers) {
        try {
          c();
        } catch (_) {}
      }
    }, (_, _) {});
    _closers.clear();
    for (final s in statuses) {
      s.active = false;
    }
  }
}

// ---------------------------------------------------------------- sessions

enum SessionState { connecting, connected, disconnected }

/// One terminal tab: a connection plus a shell, owned by [SessionManager]
/// (not by any widget), so it survives navigation.
class TerminalSession {
  final String id;
  final String title;
  final String? hostId;
  final ConnectSpec spec;
  final List<ForwardSpec> forwardSpecs;
  final String? startupCommand;
  final String encoding;
  final bool autoReconnect;
  final SessionManager _mgr;

  SessionState state = SessionState.connecting;
  String? error;
  SshFailureKind? errorKind;

  /// Seconds until the next automatic reconnect attempt, if one is scheduled.
  int? reconnectIn;

  /// Terminal output, already decoded. Set by the UI; output that arrives
  /// before it is set is buffered.
  void Function(String data)? _onData;
  final _pending = StringBuffer();

  SshConnection? _conn;
  SSHSession? _shell;
  _Forwards? _forwards;
  Sink<List<int>>? _decoder;
  Timer? _retry;
  int _attempts = 0;
  int _cols = 80, _rows = 24;
  bool _closedByUser = false;

  TerminalSession._(this._mgr, this.id, this.title, this.hostId, this.spec,
      this.forwardSpecs, this.startupCommand, this.encoding, this.autoReconnect);

  set onData(void Function(String)? f) {
    _onData = f;
    if (f != null && _pending.isNotEmpty) {
      f(_pending.toString());
      _pending.clear();
    }
  }

  List<ForwardStatus> get forwards => _forwards?.statuses ?? const [];
  SSHClient? get client => _conn?.client;

  void _emit(String s) {
    final f = _onData;
    if (f != null) {
      f(s);
    } else if (_pending.length < 1 << 20) {
      _pending.write(s);
    }
  }

  void _note(String s) => _emit('\r\n\x1b[2m$s\x1b[0m\r\n');

  /// Runs in its own error zone: once a connection is closed, the SSH
  /// library can still complete pending operations with errors that nobody
  /// awaits. Those must not crash the app.
  Future<void> connect() {
    final done = Completer<void>();
    runZonedGuarded(() => _connect().whenComplete(done.complete), (_, _) {
      if (!done.isCompleted) done.complete();
    });
    return done.future;
  }

  Future<void> _connect() async {
    _retry?.cancel();
    reconnectIn = null;
    _closedByUser = false;
    state = SessionState.connecting;
    error = null;
    errorKind = null;
    _mgr._changed();
    try {
      final conn = await sshConnect(spec, _mgr.knownHosts, _mgr.prompts);
      if (_closedByUser) {
        conn.close();
        return;
      }
      _conn = conn;
      final shell = await conn.client
          .shell(pty: SSHPtyConfig(width: _cols, height: _rows));
      _shell = shell;
      final codec = encoding == 'latin1' ? latin1 : const Utf8Codec(allowMalformed: true);
      _decoder = codec.decoder.startChunkedConversion(_StringSink(_emit));
      shell.stdout.listen((d) => _decoder?.add(d));
      shell.stderr.listen((d) => _decoder?.add(d));
      state = SessionState.connected;
      _attempts = 0;
      _mgr._recordHost(hostId, 'connected');
      _mgr._changed();

      if (forwardSpecs.isNotEmpty) {
        _forwards = _Forwards(conn.client, _mgr._changed);
        unawaited(_forwards!.start(forwardSpecs));
      }
      if (startupCommand?.trim().isNotEmpty ?? false) {
        write('${startupCommand!.trim()}\n');
      }
      unawaited(Future.any([shell.done, conn.done])
          .catchError((_) {})
          .whenComplete(() => _ended(conn, null, null)));
    } on SshFailure catch (e) {
      _ended(null, e.message, e.kind);
    } catch (e) {
      _ended(null, 'Connection failed (${e.runtimeType}).', SshFailureKind.other);
    }
  }

  void _ended(SshConnection? conn, String? message, SshFailureKind? kind) {
    if (conn != null && !identical(conn, _conn)) return;
    final wasConnected = state == SessionState.connected;
    _forwards?.stop();
    _conn?.close();
    _conn = null;
    _shell = null;
    _decoder = null;
    state = SessionState.disconnected;
    error = message ?? (_closedByUser ? null : 'Connection closed.');
    errorKind = kind;
    if (!_closedByUser) {
      _note(error ?? 'Disconnected.');
      _mgr._recordHost(hostId, wasConnected ? 'disconnected' : 'failed');
      // Retry only what a retry can fix: not auth, host key or cancel.
      final retryable = kind == null ||
          kind == SshFailureKind.unreachable ||
          kind == SshFailureKind.disconnected;
      if (autoReconnect && retryable && _attempts < 8) {
        final wait = [2, 5, 10, 20, 30, 60, 60, 60][_attempts++];
        reconnectIn = wait;
        _retry = Timer(Duration(seconds: wait), connect);
      }
    }
    _mgr._changed();
  }

  void write(String data) {
    final s = _shell;
    if (s == null) return;
    s.write(Uint8List.fromList(
        encoding == 'latin1' ? latin1.encode(data) : utf8.encode(data)));
  }

  void resize(int cols, int rows) {
    if (cols <= 0 || rows <= 0) return;
    _cols = cols;
    _rows = rows;
    try {
      _shell?.resizeTerminal(cols, rows);
    } catch (_) {}
  }

  void disconnect() {
    _closedByUser = true;
    _retry?.cancel();
    reconnectIn = null;
    final c = _conn;
    if (c != null) {
      _ended(c, null, null);
    } else {
      state = SessionState.disconnected;
      _mgr._changed();
    }
  }

  void cancelReconnect() {
    _retry?.cancel();
    reconnectIn = null;
    _mgr._changed();
  }
}

class _StringSink implements Sink<String> {
  final void Function(String) f;
  _StringSink(this.f);
  @override
  void add(String data) => f(data);
  @override
  void close() {}
}

/// Owns every open session.
class SessionManager {
  final Store store;
  final KnownHosts knownHosts;
  SshPrompts prompts;
  final sessions = <TerminalSession>[];
  final _changes = StreamController<void>.broadcast();
  int _next = 1;

  SessionManager(this.store, this.prompts) : knownHosts = KnownHosts(store);

  Stream<void> get changes => _changes.stream;
  void _changed() {
    if (!_changes.isClosed) _changes.add(null);
  }

  int get activeCount =>
      sessions.where((s) => s.state != SessionState.disconnected).length;

  void _recordHost(String? hostId, String status) {
    if (hostId == null) return;
    store.kvSetJson('hoststate:$hostId', {
      ...store.kvJson('hoststate:$hostId'),
      'status': status,
      if (status == 'connected')
        'last_connected_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  /// Opens a session for a saved host.
  TerminalSession openHost(Rec host, {int defaultKeepalive = 30}) {
    final spec =
        ConnectSpec.fromHost(store, host, defaultKeepalive: defaultKeepalive);
    return open(spec,
        hostId: host.id,
        forwards: [
          for (final f in host.list<Map>('forwards')) ForwardSpec.fromJson(f)
        ],
        startupCommand: host.get<String>('startup_command'),
        encoding: host.str('encoding', 'utf8'),
        autoReconnect: host.flag('auto_reconnect'));
  }

  TerminalSession open(ConnectSpec spec,
      {String? hostId,
      List<ForwardSpec> forwards = const [],
      String? startupCommand,
      String encoding = 'utf8',
      bool autoReconnect = false}) {
    final s = TerminalSession._(this, 's${_next++}', spec.label, hostId, spec,
        forwards, startupCommand, encoding, autoReconnect);
    sessions.add(s);
    _changed();
    unawaited(s.connect());
    return s;
  }

  void close(TerminalSession s) {
    s.disconnect();
    sessions.remove(s);
    _changed();
  }

  void closeAll() {
    for (final s in [...sessions]) {
      close(s);
    }
  }

  Map<String, dynamic> hostState(String hostId) => store.kvJson('hoststate:$hostId');
}
