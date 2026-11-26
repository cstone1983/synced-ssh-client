import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

/// Small native helpers. Android: screenshots and the clipboard. Windows:
/// idle time and the Windows lock screen (app/windows/runner).
class Native {
  static const _ch = MethodChannel('sshsync/platform');

  /// Windows: called when the Windows session is locked (Win+L, lid, idle
  /// lock screen).
  static void Function()? onSessionLocked;

  /// Starts listening for calls from the native side. Call once at start.
  static void listen() {
    if (!Platform.isWindows) return;
    _ch.setMethodCallHandler((call) async {
      if (call.method == 'sessionLocked') onSessionLocked?.call();
      return null;
    });
  }

  /// Windows: seconds since the last keyboard or mouse input anywhere on
  /// the PC. Null elsewhere or if it cannot be read.
  static Future<int?> idleSeconds() async {
    if (!Platform.isWindows) return null;
    try {
      return await _ch.invokeMethod<int>('idleSeconds');
    } catch (_) {
      return null;
    }
  }

  /// FLAG_SECURE: blocks screenshots and hides the app in the recents view.
  static Future<void> setSecure(bool on) async {
    if (!Platform.isAndroid) return;
    try {
      await _ch.invokeMethod('setSecure', on);
    } catch (_) {}
  }

  /// Copies a secret. On Android 13+ it is flagged sensitive so the system
  /// does not preview it. Cleared after 30 seconds if still on the clipboard.
  static Future<void> copySecret(String text) async {
    var done = false;
    if (Platform.isAndroid) {
      try {
        await _ch.invokeMethod('copySensitive', text);
        done = true;
      } catch (_) {}
    }
    if (!done) await Clipboard.setData(ClipboardData(text: text));
    Timer(const Duration(seconds: 30), () async {
      final cur = await Clipboard.getData(Clipboard.kTextPlain);
      if (cur?.text == text) await Clipboard.setData(const ClipboardData(text: ''));
    });
  }
}

enum BioRead { ok, missing, failed }

/// Secrets that must be available before the vault is unlocked, or that
/// unlock it: kept in the OS keystore (Android Keystore / Windows DPAPI).
class SecureStore {
  static const _plain = FlutterSecureStorage();
  static const _bioKey = 'bio_vault_key';

  // Android: the key is bound to a Keystore key that only a strong biometric
  // can release, and every read shows the system prompt. Without
  // requireBiometricsPerOperation the plugin keeps the unlocked cipher in
  // memory after the first prompt, so later unlocks (after auto-lock) would
  // read the vault key with no prompt at all. Writing (turning it on) asks
  // too. The Keystore key is invalidated when a fingerprint is added; the
  // plugin then drops this namespace's data and reads come back empty.
  static const _bio = FlutterSecureStorage(
    aOptions: AndroidOptions.biometric(
      enforceBiometrics: true,
      requireBiometricsPerOperation: true,
      biometricType: AndroidBiometricType.strongBiometricOnly,
      storageNamespace: 'sshsync_bio',
      biometricPromptTitle: 'Unlock vault',
      biometricPromptSubtitle: 'Confirm it is you',
    ),
  );

  Future<String?> read(String key) async {
    try {
      return await _plain.read(key: key);
    } catch (_) {
      return null;
    }
  }

  Future<void> write(String key, String? value) async {
    if (value == null) {
      await _plain.delete(key: key);
    } else {
      await _plain.write(key: key, value: value);
    }
  }

  // Windows Hello is off for now: local_auth only asks Hello yes or no, so
  // the vault key would sit in Credential Manager readable by any program
  // running as you. A Hello-bound key (KeyCredentialManager) comes later.
  static bool get biometricsPossible => Platform.isAndroid;

  Future<bool> biometricsAvailable() async {
    if (!biometricsPossible) return false;
    try {
      final auth = LocalAuthentication();
      return await auth.isDeviceSupported() && await auth.canCheckBiometrics;
    } catch (_) {
      return false;
    }
  }

  Future<void> storeBiometricKey(String keyBase64) async {
    if (!Platform.isAndroid) throw UnsupportedError('biometric unlock is Android only');
    await _bio.write(key: _bioKey, value: keyBase64);
  }

  /// [BioRead.missing] means the prompt was passed but no key is stored any
  /// more (on Android: a fingerprint was added, which invalidates the key).
  /// [BioRead.failed] means the prompt was cancelled or failed.
  Future<({BioRead state, String? key})> readBiometricKey() async {
    try {
      if (!Platform.isAndroid) return (state: BioRead.failed, key: null);
      final k = await _bio.read(key: _bioKey);
      return k == null || k.isEmpty
          ? (state: BioRead.missing, key: null)
          : (state: BioRead.ok, key: k);
    } on PlatformException catch (e) {
      // A fingerprint added while the app was running: the plugin only
      // clears the dead key on its next start, so recognise it here too.
      final text = '${e.message} ${e.details}';
      if (text.contains('KeyPermanentlyInvalidated')) {
        return (state: BioRead.missing, key: null);
      }
      return (state: BioRead.failed, key: null);
    } catch (_) {
      return (state: BioRead.failed, key: null);
    }
  }

  /// On Windows this removes a key stored by an earlier build that had the
  /// Hello switch (kept in Credential Manager under the same name).
  Future<void> clearBiometricKey() async {
    try {
      await (Platform.isAndroid ? _bio : _plain).delete(key: _bioKey);
    } catch (_) {}
  }
}

/// Android foreground service that keeps the process (and so the SSH
/// sockets, which live in the main isolate) alive in the background.
class SessionKeeper {
  static bool _init = false;
  static bool _running = false;
  static void Function()? onDisconnectAll;

  static Future<void> update(int sessions) async {
    if (!Platform.isAndroid) return;
    try {
      if (sessions == 0) {
        if (_running) {
          _running = false;
          await FlutterForegroundTask.stopService();
        }
        return;
      }
      final text =
          '$sessions SSH session${sessions == 1 ? '' : 's'} active';
      if (!_init) {
        _init = true;
        FlutterForegroundTask.initCommunicationPort();
        FlutterForegroundTask.addTaskDataCallback((data) {
          if (data == 'disconnect_all') onDisconnectAll?.call();
        });
        FlutterForegroundTask.init(
          androidNotificationOptions: AndroidNotificationOptions(
            channelId: 'sessions',
            channelName: 'Active SSH sessions',
            channelDescription: 'Shown while SSH sessions are open.',
          ),
          iosNotificationOptions: const IOSNotificationOptions(),
          foregroundTaskOptions: ForegroundTaskOptions(
            eventAction: ForegroundTaskEventAction.nothing(),
            allowWakeLock: true,
            allowWifiLock: true,
          ),
        );
      }
      if (_running) {
        await FlutterForegroundTask.updateService(
            notificationTitle: 'SSH Sync', notificationText: text);
        return;
      }
      if (await FlutterForegroundTask.checkNotificationPermission() !=
          NotificationPermission.granted) {
        await FlutterForegroundTask.requestNotificationPermission();
      }
      final r = await FlutterForegroundTask.startService(
        serviceTypes: [ForegroundServiceTypes.specialUse],
        notificationTitle: 'SSH Sync',
        notificationText: text,
        notificationButtons: const [
          NotificationButton(id: 'disconnect_all', text: 'Disconnect all'),
        ],
        callback: keepAliveCallback,
      );
      _running = r is ServiceRequestSuccess;
    } catch (_) {}
  }

  static Future<bool> batteryExempt() async {
    if (!Platform.isAndroid) return true;
    try {
      return await FlutterForegroundTask.isIgnoringBatteryOptimizations;
    } catch (_) {
      return true;
    }
  }

  static Future<void> requestBatteryExemption() async {
    try {
      await FlutterForegroundTask.requestIgnoreBatteryOptimization();
    } catch (_) {}
  }
}

@pragma('vm:entry-point')
void keepAliveCallback() =>
    FlutterForegroundTask.setTaskHandler(_KeepAliveHandler());

class _KeepAliveHandler extends TaskHandler {
  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {}
  @override
  void onRepeatEvent(DateTime timestamp) {}
  @override
  Future<void> onDestroy(DateTime timestamp, bool isTimeout) async {}
  @override
  void onNotificationButtonPressed(String id) =>
      FlutterForegroundTask.sendDataToMain(id);
  @override
  void onNotificationPressed() => FlutterForegroundTask.launchApp();
}
