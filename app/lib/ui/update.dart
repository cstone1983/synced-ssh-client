import 'dart:io';

import 'package:flutter/material.dart';

import '../services.dart';
import '../updater.dart';
import 'dialogs.dart';

bool _checkedThisRun = false;

/// Windows: once per run after unlock, if "Check when the app starts" is on.
Future<void> checkForUpdatesOnStart(BuildContext context) async {
  if (!Platform.isWindows || _checkedThisRun || isDevBuild) return;
  if (!App.i.setting<bool>('update_check')) return;
  _checkedThisRun = true;
  try {
    final u = await Updater.check();
    if (u != null && context.mounted) await offerUpdate(context, u);
  } catch (_) {
    // Offline or GitHub unreachable: say nothing, try again next start.
  }
}

/// The Settings button.
Future<void> checkForUpdatesNow(BuildContext context) async {
  if (isDevBuild) return toast(context, 'This is a development build, so it does not update itself.');
  toast(context, 'Checking for updates…');
  try {
    final u = await Updater.check();
    if (!context.mounted) return;
    if (u == null) return toast(context, 'You have the newest version ($appVersion).');
    await offerUpdate(context, u);
  } catch (e) {
    if (context.mounted) toast(context, 'Could not check for updates: $e');
  }
}

Future<void> offerUpdate(BuildContext context, WindowsUpdate u) async {
  final open = App.i.sessions.sessions.length;
  final ok = await confirm(
    context,
    'SSH Sync ${u.version} is available',
    'You have $appVersion. Installing downloads the new installer from GitHub, checks it against its published checksum, '
        'then closes the app${open > 0 ? ' and its $open open SSH session${open == 1 ? '' : 's'}' : ''} '
        'and reopens it when the update is done. Your vault and settings stay as they are.',
    action: 'Install',
  );
  if (!ok || !context.mounted) return;

  final progress = ValueNotifier<double?>(null);
  var cancelled = false;
  final nav = Navigator.of(context);
  showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (c) => AlertDialog(
      title: Text('Downloading ${u.version}'),
      content: ValueListenableBuilder<double?>(
        valueListenable: progress,
        builder: (c, v, _) => Column(mainAxisSize: MainAxisSize.min, children: [
          LinearProgressIndicator(value: v),
          const SizedBox(height: 12),
          Text(v == null ? 'Starting…' : '${(v * 100).round()}%'),
        ]),
      ),
      actions: [
        TextButton(
            onPressed: () {
              cancelled = true;
              Navigator.pop(c);
            },
            child: const Text('Cancel')),
      ],
    ),
  );
  try {
    final file = await Updater.download(u, onProgress: (v) => progress.value = v);
    if (cancelled) {
      try {
        file.deleteSync();
      } catch (_) {}
      return;
    }
    // Close sessions cleanly so the next start does not report them as
    // dropped by a crash.
    App.i.sessions.closeAll();
    App.i.store.kvSet('open_sessions', '0');
    await Updater.install(file);
  } catch (e) {
    if (!cancelled && nav.mounted) nav.pop();
    if (!cancelled && context.mounted) toast(context, e is UpdateException ? e.message : 'Update failed: $e');
  }
}
