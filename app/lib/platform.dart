import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

/// Small native helpers (Android only; no-ops elsewhere).
class Native {
  static const _ch = MethodChannel('sshsync/platform');

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

/// Secrets that must be available before the vault is unlocked, or that
/// unlock it: kept in the OS keystore (Android Keystore / Windows DPAPI).
class SecureStore {
  static const _plain = FlutterSecureStorage();
  static const _bioKey = 'bio_vault_key';

  // Android: the key is bound to a Keystore key that only a strong biometric
  // can release, and reading it shows the system prompt.
  static const _bio = FlutterSecureStorage(
    aOptions: AndroidOptions.biometric(
      enforceBiometrics: true,
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

  static bool get biometricsPossible => Platform.isAndroid || Platform.isWindows;

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
    if (Platform.isAndroid) {
      await _bio.write(key: _bioKey, value: keyBase64);
    } else {
      // Windows: DPAPI protects the value for this Windows user; Windows
      // Hello is asked before reading, but it is a gate, not a key.
      if (!await _hello('Enable Windows Hello unlock')) {
        throw Exception('not confirmed');
      }
      await _plain.write(key: _bioKey, value: keyBase64);
    }
  }

  Future<String?> readBiometricKey() async {
    try {
      if (Platform.isAndroid) return await _bio.read(key: _bioKey);
      if (!await _hello('Unlock vault')) return null;
      return await _plain.read(key: _bioKey);
    } catch (_) {
      return null;
    }
  }

  Future<void> clearBiometricKey() async {
    try {
      await (Platform.isAndroid ? _bio : _plain).delete(key: _bioKey);
    } catch (_) {}
  }

  Future<bool> _hello(String reason) async {
    try {
      return await LocalAuthentication()
          .authenticate(localizedReason: reason, biometricOnly: false);
    } catch (_) {
      return false;
    }
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
