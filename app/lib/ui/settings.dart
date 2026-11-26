import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:sshsync_core/sshsync_core.dart';

import '../platform.dart';
import '../services.dart';
import '../theme.dart';
import '../updater.dart';
import 'dialogs.dart';
import 'onboarding.dart';
import 'update.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  Future<void> _changePassphrase(BuildContext context) async {
    final cur = TextEditingController(), a = TextEditingController(), b = TextEditingController();
    String? error;
    var busy = false;
    await showDialog<void>(
      context: context,
      builder: (c) => StatefulBuilder(
        builder: (c, set) => AlertDialog(
          title: const Text('Change master passphrase'),
          content: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              PassphraseField(cur, label: 'Current passphrase', autofocus: true),
              const SizedBox(height: 12),
              PassphraseField(a, label: 'New passphrase'),
              const SizedBox(height: 12),
              PassphraseField(b, label: 'Repeat new passphrase'),
              const SizedBox(height: 12),
              Text('Your data is not re-encrypted; only the key that protects it is re-wrapped. Other devices pick up the new passphrase at their next sync.',
                  style: Theme.of(c).textTheme.bodySmall),
              if (error != null) Padding(padding: const EdgeInsets.only(top: 12), child: Text(error!, style: TextStyle(color: Theme.of(c).colorScheme.error))),
            ]),
          ),
          actions: [
            TextButton(onPressed: busy ? null : () => Navigator.pop(c), child: const Text('Cancel')),
            FilledButton(
              onPressed: busy
                  ? null
                  : () async {
                      if (a.text.length < 12) return set(() => error = 'Use at least 12 characters.');
                      if (a.text != b.text) return set(() => error = 'The new passphrases do not match.');
                      set(() {
                        busy = true;
                        error = null;
                      });
                      try {
                        await App.i.changePassphrase(cur.text, a.text);
                        if (c.mounted) Navigator.pop(c);
                        if (context.mounted) toast(context, 'Passphrase changed.');
                      } on CryptoException {
                        set(() {
                          busy = false;
                          error = 'The current passphrase is wrong.';
                        });
                      }
                    },
              child: const Text('Change'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _export(BuildContext context) async {
    final pass = await askText(context, 'Export encrypted backup',
        body: 'The file is protected by this passphrase alone, so use a strong one (your master passphrase is fine). '
            'It restores on any device, with or without a server.',
        label: 'Backup passphrase',
        secret: true,
        action: 'Export');
    if (pass == null || !context.mounted) return;
    if (pass.length < 12) return toast(context, 'Use at least 12 characters for the backup passphrase.');
    try {
      final file = await Backup.export(App.i.store, pass);
      final d = DateTime.now();
      final name = 'sshsync-backup-${d.year}${d.month.toString().padLeft(2, '0')}${d.day.toString().padLeft(2, '0')}.sshsync';
      final saved = await FilePicker.saveFile(fileName: name, bytes: utf8.encode(file));
      if (context.mounted && saved != null) toast(context, 'Backup saved.');
    } catch (_) {
      if (context.mounted) toast(context, 'Could not save the backup.');
    }
  }

  Future<void> _import(BuildContext context) async {
    final bytes = await pickFileBytes();
    if (bytes == null || !context.mounted) return;
    final pass = await askText(context, 'Import backup',
        body: 'Records are merged into this vault; for anything that exists in both, the newer change wins.',
        label: 'Backup passphrase',
        secret: true,
        action: 'Import');
    if (pass == null) return;
    try {
      final n = await Backup.import(App.i.store, utf8.decode(bytes), pass);
      if (context.mounted) toast(context, 'Merged $n records from the backup.');
    } on CryptoException {
      if (context.mounted) toast(context, 'Wrong passphrase, or the file was modified.');
    } catch (_) {
      if (context.mounted) toast(context, 'That is not a backup file.');
    }
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: App.i,
        builder: (context, _) {
          final app = App.i;
          final scheme = Theme.of(context).colorScheme;
          Widget section(String s) => Padding(
              padding: const EdgeInsets.fromLTRB(16, 22, 16, 4),
              child: Text(s.toUpperCase(), style: Theme.of(context).textTheme.labelMedium?.copyWith(color: scheme.onSurfaceVariant, letterSpacing: 0.8)));
          Widget choice<T>(String title, String key, Map<T, String> options, {String? subtitle}) => ListTile(
                title: Text(title),
                subtitle: subtitle == null ? null : Text(subtitle),
                trailing: DropdownButton<T>(
                  value: options.containsKey(app.setting<T>(key)) ? app.setting<T>(key) : options.keys.first,
                  underline: const SizedBox(),
                  items: [for (final e in options.entries) DropdownMenuItem(value: e.key, child: Text(e.value))],
                  onChanged: (v) => app.setSetting(key, v as Object),
                ),
              );
          return Scaffold(
            appBar: AppBar(title: const Text('Settings')),
            body: ListView(padding: const EdgeInsets.only(bottom: 40), children: [
              Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 640),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                    section('Appearance'),
                    choice<String>('App theme', 'theme', const {'dark': 'Dark', 'light': 'Light'}),
                    choice<String>('Terminal theme', 'term_theme', {for (final e in terminalThemes.entries) e.key: e.value.$1}),
                    ListTile(
                      title: const Text('Terminal font size'),
                      subtitle: Slider(
                        min: 8,
                        max: 32,
                        divisions: 24,
                        label: '${app.setting<double>('font_size').round()}',
                        value: app.setting<double>('font_size').clamp(8, 32),
                        onChanged: (v) => app.setSetting('font_size', v.roundToDouble()),
                      ),
                      trailing: Text('${app.setting<double>('font_size').round()} pt', style: const TextStyle(fontFamily: mono)),
                    ),
                    const ListTile(title: Text('Terminal font'), subtitle: Text('JetBrains Mono (bundled)')),
                    if (Platform.isAndroid)
                      SwitchListTile(
                          title: const Text('Volume keys change font size'),
                          value: app.setting<bool>('volume_zoom'),
                          onChanged: (v) => app.setSetting('volume_zoom', v)),
                    section('Terminal'),
                    choice<int>('Scrollback lines', 'scrollback', const {1000: '1,000', 5000: '5,000', 10000: '10,000', 50000: '50,000'},
                        subtitle: 'Applies to new sessions'),
                    choice<int>('Default keepalive', 'keepalive', const {0: 'Off', 15: '15 s', 30: '30 s', 60: '60 s', 120: '2 min'}),
                    section('Security'),
                    choice<int>('Auto-lock after', 'auto_lock_minutes', const {1: '1 minute', 5: '5 minutes', 15: '15 minutes', 60: '1 hour', 0: 'Never'},
                        subtitle: Platform.isAndroid
                            ? 'Time in the background'
                            : Platform.isWindows
                                ? 'Time minimised or with no keyboard or mouse use. Locking Windows locks the vault too.'
                                : 'Time minimised'),
                    if (SecureStore.biometricsPossible)
                      SwitchListTile(
                        title: const Text('Unlock with fingerprint or face'),
                        subtitle: const Text('The vault key is held by the Android Keystore and released only by a strong biometric, asked for on every unlock. '
                            'Adding a fingerprint to the phone turns this off.'),
                        isThreeLine: true,
                        value: app.biometricEnabled,
                        onChanged: (v) async {
                          try {
                            if (v && !await app.secure.biometricsAvailable()) {
                              if (context.mounted) toast(context, 'No biometrics are set up on this device.');
                              return;
                            }
                            await app.setBiometric(v);
                          } catch (_) {
                            if (context.mounted) toast(context, 'Could not turn on biometric unlock.');
                          }
                        },
                      ),
                    if (Platform.isAndroid)
                      SwitchListTile(
                          title: const Text('Block screenshots everywhere'),
                          subtitle: const Text('Vault, credential and enrollment screens are always protected'),
                          value: app.setting<bool>('secure_everywhere'),
                          onChanged: (v) => app.setSetting('secure_everywhere', v)),
                    ListTile(title: const Text('Change master passphrase'), trailing: const Icon(Icons.chevron_right), onTap: () => _changePassphrase(context)),
                    ListTile(title: const Text('Lock now'), leading: const Icon(Icons.lock_outline), onTap: app.lock),
                    if (Platform.isAndroid) ...[
                      section('Background sessions'),
                      FutureBuilder<bool>(
                        future: SessionKeeper.batteryExempt(),
                        builder: (context, snap) => ListTile(
                          title: const Text('Battery optimisation'),
                          subtitle: Text(snap.data == true
                              ? 'Not restricted. Sessions are kept alive by a notification while open.'
                              : 'Android may pause this app in the background and drop SSH sessions. Allow unrestricted battery use to keep them alive.'),
                          isThreeLine: true,
                          trailing: snap.data == true ? Icon(Icons.check_circle, color: scheme.primary) : TextButton(onPressed: SessionKeeper.requestBatteryExemption, child: const Text('Allow')),
                        ),
                      ),
                    ],
                    section('Sync'),
                    choice<int>('Sync every', 'sync_interval', const {30: '30 s', 60: '1 minute', 300: '5 minutes', 900: '15 minutes'},
                        subtitle: 'While the app is open and unlocked. Server address is on the Sync screen.'),
                    if (Platform.isWindows) ...[
                      section('Updates'),
                      ListTile(
                        title: const Text('Check for updates'),
                        subtitle: Text('Version $appVersion. New versions come from GitHub releases.'),
                        leading: const Icon(Icons.system_update_alt),
                        onTap: () => checkForUpdatesNow(context),
                      ),
                      SwitchListTile(
                          title: const Text('Check when the app starts'),
                          value: app.setting<bool>('update_check'),
                          onChanged: (v) => app.setSetting('update_check', v)),
                    ],
                    section('Backup'),
                    const Padding(
                      padding: EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                      child: WarningBox('A lost master passphrase cannot be recovered. An encrypted backup file is your safety net against losing every device.',
                          icon: Icons.info_outline),
                    ),
                    ListTile(title: const Text('Export encrypted backup'), leading: const Icon(Icons.save_alt), onTap: () => _export(context)),
                    ListTile(title: const Text('Import encrypted backup'), leading: const Icon(Icons.file_open_outlined), onTap: () => _import(context)),
                    section('Danger zone'),
                    ListTile(
                      title: Text('Erase this device', style: TextStyle(color: scheme.error)),
                      subtitle: const Text('Removes the vault, hosts and sync setup from this device only'),
                      onTap: () async {
                        if (await confirm(context, 'Erase this device?',
                            'Everything stored by this app on this device is deleted. Other devices and the server are not affected.',
                            action: 'Erase', danger: true)) {
                          await app.resetDevice();
                        }
                      },
                    ),
                  ]),
                ),
              ),
            ]),
          );
        },
      );
}
