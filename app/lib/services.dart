import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:sshsync_core/sshsync_core.dart';

import 'platform.dart';

enum BioUnlock { unlocked, failed, reset }

/// App-wide services and state. One instance, created at startup.
class App extends ChangeNotifier {
  static late App i;

  final SodiumCrypto crypto;
  final Vault vault;
  final Store store;
  final SessionManager sessions;
  final secure = SecureStore();
  late final SyncService sync = SyncService(this);

  /// Sessions that were open when the app last stopped unexpectedly.
  int interruptedSessions = 0;

  App._(this.crypto, this.vault, this.store, this.sessions) {
    store.changes.listen((_) => notifyListeners());
    // If the previous run ended with sessions still open, the OS (or a
    // crash) took them down. Remember that so the user can be told.
    interruptedSessions = int.tryParse(store.kvGet('open_sessions') ?? '') ?? 0;
    store.kvSet('open_sessions', '0');
    sessions.changes.listen((_) {
      store.kvSet('open_sessions', '${sessions.activeCount}');
      SessionKeeper.update(sessions.activeCount);
      notifyListeners();
    });
    SessionKeeper.onDisconnectAll = () {
      for (final s in sessions.sessions) {
        s.disconnect();
      }
    };
  }

  static Future<App> start(SshPrompts prompts, {String? directory}) async {
    final crypto = await SodiumCrypto.load();
    final vault = Vault(crypto);
    final dir = directory ?? (await getApplicationSupportDirectory()).path;
    Directory(dir).createSync(recursive: true);
    final store = Store.open('$dir/sshsync.db', vault);
    final app = i = App._(crypto, vault, store, SessionManager(store, prompts));
    if (Platform.isWindows) {
      // Windows Hello unlock was removed: drop any key an earlier build left.
      await app.secure.clearBiometricKey();
      if (store.kvGet('biometric') != null) store.kvSet('biometric', null);
    }
    return app;
  }

  /// Tell listeners something outside the store changed.
  void touch() => notifyListeners();

  // ---------------------------------------------------------------- vault

  Keyslot? get keyslot {
    final k = store.kvGet('keyslot');
    return k == null ? null : Keyslot.decode(k);
  }

  bool get hasVault => store.kvGet('keyslot') != null;
  bool get unlocked => vault.isUnlocked;
  bool get biometricEnabled => store.kvGet('biometric') == '1';

  Future<void> createVault(String passphrase) async {
    final slot = await vault.create(passphrase);
    store.kvSet('keyslot', slot.encode());
    _afterUnlock();
  }

  /// Throws [CryptoException] on a wrong passphrase.
  Future<void> unlock(String passphrase) async {
    await vault.unlock(keyslot!, passphrase);
    _afterUnlock();
  }

  Future<BioUnlock> unlockWithBiometrics() async {
    final r = await secure.readBiometricKey();
    if (r.state == BioRead.failed) return BioUnlock.failed;
    if (r.state == BioRead.missing) {
      // The OS dropped the key (a fingerprint was added). It cannot come
      // back, so turn the setting off rather than prompting forever.
      await setBiometric(false);
      return BioUnlock.reset;
    }
    try {
      vault.unlockWithKey(base64.decode(r.key!));
      // Prove the stored key is this vault's key before trusting it.
      final check = store.kvGet('key_check');
      if (check != null) vault.openLocal('key_check', base64.decode(check));
    } catch (_) {
      vault.lock();
      await setBiometric(false);
      return BioUnlock.reset;
    }
    _afterUnlock();
    return BioUnlock.unlocked;
  }

  void _afterUnlock() {
    if (store.kvGet('key_check') == null) {
      store.kvSet('key_check',
          base64.encode(vault.sealLocal('key_check', utf8.encode('ok'))));
    }
    _cacheSettings();
    sync.onUnlock();
    notifyListeners();
  }

  /// Wipes the vault key from memory. Open SSH sessions keep running.
  void lock() {
    if (!vault.isUnlocked) return;
    sync.onLock();
    vault.lock();
    notifyListeners();
  }

  Future<void> setBiometric(bool on) async {
    if (on) {
      final key = vault.exportKey();
      try {
        await secure.storeBiometricKey(base64.encode(key));
      } finally {
        zero(key);
      }
      store.kvSet('biometric', '1', notify: true);
    } else {
      await secure.clearBiometricKey();
      store.kvSet('biometric', null, notify: true);
    }
  }

  /// Re-wraps the vault key; no record is re-encrypted.
  Future<void> changePassphrase(String current, String next) async {
    final slot = keyslot!;
    if (!await vault.verify(slot, current)) {
      throw const CryptoException('wrong passphrase');
    }
    final fresh = await vault.changePassphrase(slot, next);
    store.kvSet('keyslot', fresh.encode());
    SyncEngine.markKeyslotChanged(store);
    sync.syncNow();
  }

  /// Erases everything on this device.
  Future<void> resetDevice() async {
    sessions.closeAll();
    sync.onLock();
    vault.lock();
    await secure.clearBiometricKey();
    await secure.write('sync_token', null);
    await secure.write('sync_token_pending', null);
    await secure.write('sync_key', null);
    store.wipe();
    notifyListeners();
  }

  // ---------------------------------------------------------------- settings

  static const _synced = {'theme', 'term_theme', 'scrollback', 'keepalive'};
  static const _defaults = <String, Object>{
    'theme': 'dark',
    'term_theme': 'default',
    'scrollback': 5000,
    'keepalive': 30,
    'font_size': 14.0,
    'auto_lock_minutes': 15,
    'sync_interval': 60,
    'secure_everywhere': false,
    'volume_zoom': false,
    'update_check': true,
  };

  /// Synced settings are records (so they follow you); the rest are local.
  /// A local copy of synced settings lets the theme apply before unlock.
  T setting<T>(String key) {
    Object? v;
    if (_synced.contains(key) && vault.isUnlocked) {
      v = store.get(vault.deterministicId('setting|$key'))?.fields['value'];
    }
    v ??= store.kvJson('settings')[key];
    v ??= _defaults[key];
    if (T == double && v is num) return v.toDouble() as T;
    if (T == int && v is num) return v.toInt() as T;
    return v as T;
  }

  void setSetting(String key, Object value) {
    if (_synced.contains(key) && vault.isUnlocked) {
      store.put(RecordType.setting,
          id: vault.deterministicId('setting|$key'),
          {'key': key, 'value': value});
    }
    store.kvSetJson('settings', {...store.kvJson('settings'), key: value});
    if (key == 'sync_interval') sync.restart();
  }

  void _cacheSettings() {
    final cache = store.kvJson('settings');
    for (final k in _synced) {
      final v = store.get(vault.deterministicId('setting|$k'))?.fields['value'];
      if (v != null) cache[k] = v;
    }
    store.kvSetJson('settings', cache, notify: false);
  }

  // ---------------------------------------------------------------- data helpers

  List<Rec> get hosts => store.list(RecordType.host);
  List<Rec> get groups => store.list(RecordType.group)
    ..sort((a, b) => a.str('name').toLowerCase().compareTo(b.str('name').toLowerCase()));
  List<Rec> get credentials => store.list(RecordType.credential)
    ..sort((a, b) => a.str('label').toLowerCase().compareTo(b.str('label').toLowerCase()));
  List<Rec> get conflicts => store.list(RecordType.conflict)
    ..sort((a, b) => b.integer('created_at').compareTo(a.integer('created_at')));

  TerminalSession connect(Rec host) =>
      sessions.openHost(host, defaultKeepalive: setting<int>('keepalive'));

  /// Adds imported hosts, skipping ones already present (same hostname and
  /// port). Returns how many were added.
  int importHosts(List<ImportedHost> items) {
    final existing = {
      for (final h in hosts) '${h.str('hostname').toLowerCase()}:${h.integer('port', 22)}'
    };
    final groupIds = {for (final g in groups) g.str('name').toLowerCase(): g.id};
    final creds = {for (final c in credentials) c.str('username'): c.id};
    final byName = <String, String>{};
    var added = 0;
    for (final h in items) {
      final key = '${h.hostname.toLowerCase()}:${h.port}';
      if (existing.contains(key)) continue;
      existing.add(key);
      String? groupId;
      final g = h.group?.trim();
      if (g != null && g.isNotEmpty) {
        groupId = groupIds[g.toLowerCase()] ??=
            store.put(RecordType.group, {'name': g});
      }
      byName[h.nickname] = store.put(RecordType.host, {
        'nickname': h.nickname,
        'hostname': h.hostname,
        'port': h.port,
        'credential_id': h.user == null ? null : creds[h.user],
        'auth_order': AuthOrder.keyThenPassword,
        'group_id': groupId,
        'tags': h.tags,
        'notes': [
          if (h.user != null && creds[h.user] == null) 'User: ${h.user}',
          if (h.identityFile != null) 'Key file: ${h.identityFile}',
        ].join('\n'),
      });
      added++;
    }
    // Second pass: link jump hosts by nickname.
    for (final h in items) {
      final id = byName[h.nickname], via = byName[h.proxyJump];
      if (id != null && via != null) store.update(id, {'jump_host_id': via});
    }
    return added;
  }
}

/// Sync wiring: configuration, enrollment and the engine's lifetime.
class SyncService {
  final App app;
  SyncEngine? engine;
  HttpSyncApi? api;
  StreamSubscription<SyncStatus>? _sub;
  SyncService(this.app);

  Store get _store => app.store;

  Map<String, dynamic> get config => _store.kvJson('sync');
  bool get configured => config['url'] != null;
  String? get url => config['url'] as String?;
  bool get insecureLan => config['allow_insecure'] == true;
  SyncStatus? get status => engine?.current;

  HttpSyncApi _api(String url, String token, String? pin,
          {String? pending, TokenSaver? save}) =>
      HttpSyncApi(url, token,
          client: (pin == null || pin.isEmpty) ? null : HttpSyncApi.pinnedClient(pin),
          pendingToken: pending,
          saveTokens: save);

  /// Saves the token and any unconfirmed new one from a rotation, so a
  /// rotation whose reply was lost can be finished after a restart.
  Future<void> _saveTokens(String token, String? pending) async {
    await app.secure.write('sync_token_pending', pending);
    await app.secure.write('sync_token', token);
  }

  Future<void> onUnlock() async {
    if (!configured || engine != null) return;
    final token = await app.secure.read('sync_token');
    final pending = await app.secure.read('sync_token_pending');
    final sk = await app.secure.read('sync_key');
    if (token == null || !app.unlocked) return;
    api = _api(url!, token, config['cert_pin'] as String?,
        pending: pending, save: _saveTokens);
    engine = SyncEngine(_store, api!,
        syncKey: sk == null ? null : SyncKey.parse(sk));
    _sub = engine!.status.listen((_) => app.touch());
    engine!.start(interval: Duration(seconds: app.setting<int>('sync_interval')));
  }

  void onLock() {
    _sub?.cancel();
    engine?.dispose();
    api?.close();
    engine = null;
    api = null;
  }

  void restart() {
    if (engine == null) return;
    onLock();
    onUnlock();
  }

  Future<bool> syncNow() async => await engine?.syncOnce() ?? false;

  String? checkUrl(String url, bool allowInsecure) =>
      UrlPolicy.check(url, allowInsecureLan: allowInsecure);

  String get _platform =>
      Platform.isAndroid ? 'android' : Platform.isWindows ? 'windows' : Platform.isLinux ? 'linux' : 'other';

  Future<void> _save(String url, EnrollResult e, String skText,
      {required bool allowInsecure, String? pin}) async {
    await app.secure.write('sync_token', e.token);
    await app.secure.write('sync_token_pending', null);
    await app.secure.write('sync_key', skText);
    _store.resetSyncState();
    _store.kvSet('sync_cursor', null);
    _store.kvSet('keyslot_version', null);
    _store.kvSetJson('sync', {
      'url': url.trim().replaceAll(RegExp(r'/+$'), ''),
      'device_id': e.deviceId,
      'vault_id': e.vaultId,
      'allow_insecure': allowInsecure,
      'cert_pin': pin,
    });
  }

  /// Connect this (unlocked) device to a server. If the server already holds
  /// a vault, [syncKeyText] is required and must open it.
  Future<void> enroll(String url, String code, String deviceName,
      {String? syncKeyText, bool allowInsecure = false, String? pin}) async {
    final problem = checkUrl(url, allowInsecure);
    if (problem != null) throw StateError(problem);
    final client = (pin == null || pin.isEmpty) ? null : HttpSyncApi.pinnedClient(pin);
    final e = await HttpSyncApi.enroll(url, code, deviceName, _platform, client: client);
    final probe = _api(url, e.token, pin);
    try {
      final remote = await probe.getKeyslot();
      final String skText;
      if (remote == null) {
        skText = SyncKey.format(SyncKey.generate(app.crypto));
      } else {
        if (syncKeyText == null || syncKeyText.trim().isEmpty) {
          throw StateError('This server already has a vault. Enter its sync key.');
        }
        final Keyslot theirs;
        try {
          theirs = SyncKey.openKeyslot(app.crypto, SyncKey.parse(syncKeyText), remote.blob);
        } on Exception {
          throw StateError('That sync key does not match this server.');
        }
        if (theirs.vaultId != app.keyslot!.vaultId) {
          throw StateError('The server holds a different vault than this device. '
              'To join it, reset this device and choose "Join existing vault".');
        }
        skText = SyncKey.format(SyncKey.parse(syncKeyText));
      }
      await _save(url, e, skText, allowInsecure: allowInsecure, pin: pin);
    } catch (_) {
      // Do not leave a half-enrolled device on the server.
      try {
        await probe.revokeDevice(e.deviceId);
      } catch (_) {}
      rethrow;
    } finally {
      probe.close();
    }
    await onUnlock();
    await syncNow();
  }

  /// First run on a new device: fetch the vault from the server, then unlock
  /// it with the master passphrase.
  Future<void> joinExisting(String url, String code, String syncKeyText,
      String passphrase, String deviceName,
      {bool allowInsecure = false, String? pin}) async {
    final problem = checkUrl(url, allowInsecure);
    if (problem != null) throw StateError(problem);
    final sk = SyncKey.parse(syncKeyText);
    final client = (pin == null || pin.isEmpty) ? null : HttpSyncApi.pinnedClient(pin);
    final e = await HttpSyncApi.enroll(url, code, deviceName, _platform, client: client);
    final probe = _api(url, e.token, pin);
    try {
      final remote = await probe.getKeyslot();
      if (remote == null) {
        throw StateError('This server has no vault yet. Create a vault on this '
            'device first, then connect it under Sync.');
      }
      final Keyslot slot;
      try {
        slot = SyncKey.openKeyslot(app.crypto, sk, remote.blob);
      } on CryptoException {
        throw StateError('That sync key does not match this server.');
      }
      await app.vault.unlock(slot, passphrase);
      _store.kvSet('keyslot', slot.encode());
      await _save(url, e, SyncKey.format(sk), allowInsecure: allowInsecure, pin: pin);
      _store.kvSet('keyslot_version', '${remote.version}');
    } catch (_) {
      try {
        await probe.revokeDevice(e.deviceId);
      } catch (_) {}
      rethrow;
    } finally {
      probe.close();
    }
    app._afterUnlock();
    await syncNow();
  }

  /// Stop syncing on this device. Local data stays.
  Future<void> disconnect({bool revokeSelf = true}) async {
    final id = config['device_id'] as String?;
    if (revokeSelf && id != null) {
      try {
        await api?.revokeDevice(id);
      } catch (_) {}
    }
    onLock();
    await app.secure.write('sync_token', null);
    await app.secure.write('sync_token_pending', null);
    await app.secure.write('sync_key', null);
    _store.kvSet('sync', null);
    _store.kvSet('sync_cursor', null);
    _store.kvSet('sync_last_success', null);
    _store.kvSet('keyslot_version', null);
    _store.resetSyncState();
  }

  /// Text for the QR another device scans to join: server address, a
  /// one-time code and the sync key. Treat it like a password.
  Future<({String payload, String code, int expiresAt, String syncKey})> invite() async {
    final c = await api!.createEnrollmentCode();
    final sk = (await app.secure.read('sync_key'))!;
    return (
      payload: jsonEncode({
        'sshsync': 1,
        'url': url,
        'code': c.code,
        'sk': sk,
        if (config['cert_pin'] != null) 'pin': config['cert_pin'],
        if (insecureLan) 'insecure': true,
      }),
      code: c.code,
      expiresAt: c.expiresAt,
      syncKey: sk,
    );
  }

  static Map<String, dynamic>? parseInvite(String text) {
    try {
      final j = jsonDecode(text) as Map<String, dynamic>;
      return j['sshsync'] == 1 ? j : null;
    } catch (_) {
      return null;
    }
  }
}
