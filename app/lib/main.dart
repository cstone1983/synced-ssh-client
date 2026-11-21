import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'platform.dart';
import 'services.dart';
import 'theme.dart';
import 'ui/dialogs.dart';
import 'ui/onboarding.dart';
import 'ui/shell.dart';

final navKey = GlobalKey<NavigatorState>();

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await App.start(DialogPrompts(navKey));
  runApp(const SshSyncApp());
}

class SshSyncApp extends StatefulWidget {
  const SshSyncApp({super.key});
  @override
  State<SshSyncApp> createState() => _SshSyncAppState();
}

class _SshSyncAppState extends State<SshSyncApp> with WidgetsBindingObserver {
  final app = App.i;
  DateTime? _leftAt;
  Timer? _lockTimer;
  bool _wasUnlocked = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    app.addListener(_changed);
    _applySecure();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    app.removeListener(_changed);
    super.dispose();
  }

  void _changed() {
    if (_wasUnlocked && !app.unlocked) {
      // Drop every screen that might be showing secrets.
      navKey.currentState?.popUntil((r) => r.isFirst);
    }
    _wasUnlocked = app.unlocked;
    _applySecure();
    setState(() {});
  }

  void _applySecure() {
    // The lock screen is always protected; the rest follows the setting.
    // Vault and credential screens turn it on themselves.
    secureDepth.base = !app.unlocked || app.setting<bool>('secure_everywhere');
    secureDepth.apply();
  }

  /// Auto-lock: after the configured time away from the app, wipe the key.
  /// On Android "away" is backgrounded; on desktop it is minimised/hidden.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final minutes = app.setting<int>('auto_lock_minutes');
    final away = Platform.isAndroid
        ? state != AppLifecycleState.resumed
        : (state == AppLifecycleState.hidden || state == AppLifecycleState.paused);
    if (away) {
      _leftAt ??= DateTime.now();
      if (minutes > 0) {
        _lockTimer ??= Timer(Duration(minutes: minutes), app.lock);
      }
    } else if (state == AppLifecycleState.resumed) {
      _lockTimer?.cancel();
      _lockTimer = null;
      final left = _leftAt;
      _leftAt = null;
      if (minutes > 0 &&
          left != null &&
          DateTime.now().difference(left) >= Duration(minutes: minutes)) {
        app.lock();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final dark = app.setting<String>('theme') != 'light';
    return MaterialApp(
      title: 'SSH Sync',
      debugShowCheckedModeBanner: false,
      navigatorKey: navKey,
      theme: appTheme(dark),
      home: !app.hasVault
          ? const OnboardingScreen()
          : !app.unlocked
              ? const UnlockScreen()
              : const AppShell(),
    );
  }
}

/// Counts screens that asked for FLAG_SECURE so it turns off only when the
/// last one closes.
class SecureDepth {
  bool base = false;
  int count = 0;
  void apply() => Native.setSecure(base || count > 0);
}

final secureDepth = SecureDepth();

/// Wrap a screen that shows secrets: no screenshots, hidden in recents.
class Secure extends StatefulWidget {
  final Widget child;
  const Secure({super.key, required this.child});
  @override
  State<Secure> createState() => _SecureState();
}

class _SecureState extends State<Secure> {
  @override
  void initState() {
    super.initState();
    secureDepth.count++;
    secureDepth.apply();
  }

  @override
  void dispose() {
    secureDepth.count--;
    secureDepth.apply();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
