import 'dart:io';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:sshsync_core/sshsync_core.dart';

import '../main.dart';
import '../services.dart';
import '../theme.dart';
import 'dialogs.dart';

/// Rough passphrase strength: 0 weak .. 3 strong. Length matters most.
int passphraseStrength(String p) {
  if (p.length < 12) return 0;
  var classes = 0;
  if (p.contains(RegExp('[a-z]'))) classes++;
  if (p.contains(RegExp('[A-Z]'))) classes++;
  if (p.contains(RegExp('[0-9]'))) classes++;
  if (p.contains(RegExp('[^A-Za-z0-9]'))) classes++;
  final words = p.trim().split(RegExp(r'\s+')).length;
  if (p.length >= 20 || words >= 4) return 3;
  if (p.length >= 16 || classes >= 3) return 2;
  return 1;
}

class PassphraseField extends StatefulWidget {
  final TextEditingController controller;
  final String label;
  final bool autofocus;
  final ValueChanged<String>? onSubmitted;
  final ValueChanged<String>? onChanged;
  final FocusNode? focusNode;
  const PassphraseField(this.controller,
      {super.key, this.label = 'Master passphrase', this.autofocus = false, this.onSubmitted, this.onChanged, this.focusNode});
  @override
  State<PassphraseField> createState() => _PassphraseFieldState();
}

class _PassphraseFieldState extends State<PassphraseField> {
  bool hidden = true;
  @override
  Widget build(BuildContext context) => TextField(
        controller: widget.controller,
        focusNode: widget.focusNode,
        autofocus: widget.autofocus,
        obscureText: hidden,
        autocorrect: false,
        enableSuggestions: false,
        onSubmitted: widget.onSubmitted,
        onChanged: widget.onChanged,
        decoration: InputDecoration(
          labelText: widget.label,
          suffixIcon: IconButton(
            tooltip: hidden ? 'Show' : 'Hide',
            icon: Icon(hidden ? Icons.visibility : Icons.visibility_off),
            onPressed: () => setState(() => hidden = !hidden),
          ),
        ),
      );
}

class _Frame extends StatelessWidget {
  final List<Widget> children;
  const _Frame(this.children);
  @override
  Widget build(BuildContext context) => Scaffold(
        body: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: children),
              ),
            ),
          ),
        ),
      );
}

Widget _logo(BuildContext context) => Column(children: [
      Container(
        width: 64,
        height: 64,
        decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(16)),
        child: Icon(Icons.terminal, size: 34, color: Theme.of(context).colorScheme.primary),
      ),
      const SizedBox(height: 16),
    ]);

class WarningBox extends StatelessWidget {
  final String text;
  final IconData icon;
  final Color? color;
  const WarningBox(this.text, {super.key, this.icon = Icons.warning_amber_rounded, this.color});
  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.tertiary;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
          color: c.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: c.withValues(alpha: 0.5))),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(icon, color: c, size: 20),
        const SizedBox(width: 10),
        Expanded(child: Text(text)),
      ]),
    );
  }
}

/// First run: create a vault, or join one that already exists on a server.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});
  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final p1 = TextEditingController(), p2 = TextEditingController();
  bool understood = false, busy = false;
  String? error;

  Future<void> _create() async {
    if (p1.text.length < 12) return setState(() => error = 'Use at least 12 characters.');
    if (p1.text != p2.text) return setState(() => error = 'The two passphrases do not match.');
    if (!understood) return setState(() => error = 'Please confirm you understand the warning.');
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await App.i.createVault(p1.text);
    } catch (e) {
      if (mounted) setState(() => error = 'Could not create the vault.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    final strength = passphraseStrength(p1.text);
    const labels = ['Too short or weak', 'Fair', 'Good', 'Strong'];
    final colors = [t.colorScheme.error, t.colorScheme.tertiary, t.colorScheme.secondary, t.colorScheme.primary];
    return Secure(
      child: _Frame([
        _logo(context),
        Text('Create your vault', style: t.textTheme.headlineSmall, textAlign: TextAlign.center),
        const SizedBox(height: 8),
        Text('One master passphrase encrypts every password and key on this device, before anything is synced.',
            textAlign: TextAlign.center, style: TextStyle(color: t.colorScheme.onSurfaceVariant)),
        const SizedBox(height: 24),
        PassphraseField(p1, autofocus: true, onChanged: (_) => setState(() {})),
        if (p1.text.isNotEmpty) ...[
          const SizedBox(height: 8),
          Row(children: [
            Expanded(
                child: LinearProgressIndicator(
                    value: (strength + 1) / 4, color: colors[strength], minHeight: 4, borderRadius: BorderRadius.circular(2))),
            const SizedBox(width: 12),
            Text(labels[strength], style: t.textTheme.labelMedium),
          ]),
        ],
        const SizedBox(height: 12),
        PassphraseField(p2, label: 'Repeat passphrase', onSubmitted: (_) => _create()),
        const SizedBox(height: 16),
        const WarningBox('If you lose this passphrase, your data cannot be recovered. There is no reset. '
            'Keep an encrypted backup (Settings → Backup) somewhere safe.'),
        CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          controlAffinity: ListTileControlAffinity.leading,
          value: understood,
          onChanged: (v) => setState(() => understood = v ?? false),
          title: const Text('I understand it cannot be recovered'),
        ),
        if (error != null)
          Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Text(error!, style: TextStyle(color: t.colorScheme.error))),
        FilledButton(
          onPressed: busy ? null : _create,
          child: busy
              ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
              : const Text('Create vault'),
        ),
        const SizedBox(height: 8),
        TextButton(
          onPressed: busy
              ? null
              : () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const JoinScreen(firstRun: true))),
          child: const Text('I already have a vault on another device'),
        ),
      ]),
    );
  }
}

class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key});
  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final pass = TextEditingController();
  final focus = FocusNode();
  bool busy = false;
  String? error;

  @override
  void initState() {
    super.initState();
    if (App.i.biometricEnabled) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _biometric());
    }
  }

  Future<void> _biometric() async {
    if (busy) return;
    setState(() => busy = true);
    final r = await App.i.unlockWithBiometrics();
    if (mounted) {
      setState(() {
        busy = false;
        switch (r) {
          case BioUnlock.unlocked:
            break;
          case BioUnlock.failed:
            error = 'Biometric unlock did not succeed. Enter your passphrase.';
          case BioUnlock.reset:
            error = 'Fingerprint unlock was reset, because the fingerprints on this device changed. '
                'Unlock with your passphrase, then turn it on again in Settings.';
        }
      });
    }
  }

  Future<void> _unlock() async {
    if (pass.text.isEmpty || busy) return;
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await App.i.unlock(pass.text);
    } on CryptoException {
      if (mounted) {
        setState(() => error = 'Wrong passphrase.');
        pass.clear();
        focus.requestFocus();
      }
    } catch (_) {
      if (mounted) setState(() => error = 'Could not unlock.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    final active = App.i.sessions.activeCount;
    return _Frame([
      _logo(context),
      Text('Vault locked', style: t.textTheme.headlineSmall, textAlign: TextAlign.center),
      const SizedBox(height: 8),
      if (active > 0)
        Text('$active SSH session${active == 1 ? ' is' : 's are'} still running.',
            textAlign: TextAlign.center, style: TextStyle(color: t.colorScheme.onSurfaceVariant)),
      const SizedBox(height: 24),
      PassphraseField(pass, focusNode: focus, autofocus: !App.i.biometricEnabled, onSubmitted: (_) => _unlock()),
      if (error != null)
        Padding(padding: const EdgeInsets.only(top: 12), child: Text(error!, style: TextStyle(color: t.colorScheme.error))),
      const SizedBox(height: 16),
      FilledButton(
        onPressed: busy ? null : _unlock,
        child: busy
            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
            : const Text('Unlock'),
      ),
      if (App.i.biometricEnabled) ...[
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: busy ? null : _biometric,
          icon: const Icon(Icons.fingerprint),
          label: Text(Platform.isWindows ? 'Use Windows Hello' : 'Use fingerprint or face'),
        ),
      ],
    ]);
  }
}

/// Connect to a sync server. [firstRun]: this device has no vault yet and
/// downloads one. Otherwise the unlocked local vault is connected.
class JoinScreen extends StatefulWidget {
  final bool firstRun;
  const JoinScreen({super.key, required this.firstRun});
  @override
  State<JoinScreen> createState() => _JoinScreenState();
}

class _JoinScreenState extends State<JoinScreen> {
  final url = TextEditingController(), code = TextEditingController(), sk = TextEditingController();
  final pass = TextEditingController(), pin = TextEditingController();
  late final name = TextEditingController(text: _defaultName());
  bool insecure = false, busy = false, advanced = false, sending = false;
  String? error, sent;

  static String _defaultName() {
    try {
      return Platform.localHostname;
    } catch (_) {
      return Platform.isAndroid ? 'Android' : 'Device';
    }
  }

  void _applyInvite(Map<String, dynamic> j) => setState(() {
        url.text = '${j['url'] ?? ''}';
        code.text = '${j['code'] ?? ''}';
        sk.text = '${j['sk'] ?? ''}';
        pin.text = '${j['pin'] ?? ''}';
        insecure = j['insecure'] == true;
      });

  Future<void> _scan() async {
    final text = await Navigator.push<String>(context, MaterialPageRoute(builder: (_) => const _ScanScreen()));
    if (text == null || !mounted) return;
    final j = SyncService.parseInvite(text);
    if (j == null) return toast(context, 'That is not an SSH Sync enrollment code.');
    _applyInvite(j);
  }

  void _fail(String message) {
    if (mounted) setState(() => error = message);
  }

  /// The server sends a one-time code to its owner's Telegram; the user types
  /// it in below. Needs only the server address.
  Future<void> _requestCode() async {
    final sync = App.i.sync;
    final problem = sync.checkUrl(url.text, insecure);
    if (problem != null) return setState(() => error = problem);
    var deviceName = name.text.trim().isEmpty ? _defaultName() : name.text.trim();
    if (deviceName.length > 64) deviceName = deviceName.substring(0, 64);
    setState(() {
      sending = true;
      error = null;
      sent = null;
    });
    try {
      await sync.requestCode(url.text, deviceName, allowInsecure: insecure, pin: pin.text.trim());
      if (mounted) setState(() => sent = 'Code sent. Check Telegram and type it below.');
    } on ApiException catch (e) {
      _fail(switch (e.code) {
        'not_available' => 'This server is not set up to send codes. Run "sshsync enroll-code" on the server instead.',
        'not_found' => 'This server is too old to send codes. Update it, or run "sshsync enroll-code" on the server.',
        'rate_limited' => 'Too many codes requested. Wait a few minutes and try again.',
        'notify_failed' => 'The server could not send the code. Try again in a moment.',
        _ => e.message,
      });
    } on OfflineException {
      _fail('Could not reach the server. Check the address'
          '${pin.text.isEmpty ? ' (a self-signed certificate needs its fingerprint under Advanced)' : ''}.');
    } on StateError catch (e) {
      _fail(e.message);
    } catch (_) {
      _fail('Could not request a code.');
    } finally {
      if (mounted) setState(() => sending = false);
    }
  }

  Future<void> _go() async {
    final sync = App.i.sync;
    final problem = sync.checkUrl(url.text, insecure);
    if (problem != null) return setState(() => error = problem);
    if (code.text.trim().isEmpty) return setState(() => error = 'Enter the enrollment code.');
    setState(() {
      busy = true;
      error = null;
    });
    try {
      if (widget.firstRun) {
        await sync.joinExisting(url.text, code.text, sk.text, pass.text, name.text.trim(),
            allowInsecure: insecure, pin: pin.text.trim());
      } else {
        await sync.enroll(url.text, code.text, name.text.trim(),
            syncKeyText: sk.text, allowInsecure: insecure, pin: pin.text.trim());
      }
      if (mounted) Navigator.pop(context);
    } on CryptoException {
      setState(() => error = 'Wrong master passphrase.');
    } on FormatException catch (e) {
      setState(() => error = e.message);
    } on ApiException catch (e) {
      setState(() => error = e.code == 'invalid_code'
          ? 'That enrollment code is wrong, used or expired.'
          : e.code == 'rate_limited'
              ? 'Too many attempts. Wait a minute and try again.'
              : e.message);
    } on OfflineException {
      setState(() => error = 'Could not reach the server. Check the address'
          '${pin.text.isEmpty ? ' (a self-signed certificate needs its fingerprint under Advanced)' : ''}.');
    } on StateError catch (e) {
      setState(() => error = e.message);
    } catch (e) {
      setState(() => error = 'Enrollment failed.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    final http = url.text.trim().toLowerCase().startsWith('http://');
    return Secure(
      child: Scaffold(
        appBar: AppBar(title: Text(widget.firstRun ? 'Join existing vault' : 'Connect to sync server')),
        body: ListView(padding: const EdgeInsets.all(20), children: [
          Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                if (Platform.isAndroid) ...[
                  OutlinedButton.icon(onPressed: busy ? null : _scan, icon: const Icon(Icons.qr_code_scanner), label: const Text('Scan QR from another device')),
                  const SizedBox(height: 8),
                ],
                OutlinedButton.icon(
                  onPressed: busy
                      ? null
                      : () async {
                          final text = await askText(context, 'Paste enrollment text',
                              body: 'On an enrolled device: Sync → Add device → Copy.', label: 'Enrollment text');
                          final j = text == null ? null : SyncService.parseInvite(text.trim());
                          if (!context.mounted || text == null) return;
                          j == null ? toast(context, 'That is not an SSH Sync enrollment text.') : _applyInvite(j);
                        },
                  icon: const Icon(Icons.content_paste),
                  label: const Text('Paste enrollment text'),
                ),
                const SizedBox(height: 20),
                TextField(
                    controller: url,
                    keyboardType: TextInputType.url,
                    autocorrect: false,
                    onChanged: (_) => setState(() {}),
                    decoration: const InputDecoration(labelText: 'Server address', hintText: 'https://sync.example.com')),
                const SizedBox(height: 8),
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton.icon(
                    onPressed: busy || sending || url.text.trim().isEmpty ? null : _requestCode,
                    icon: sending
                        ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.send),
                    label: const Text('Send code to Telegram'),
                  ),
                ),
                if (sent != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Text(sent!, style: t.textTheme.bodySmall?.copyWith(color: t.colorScheme.primary)),
                  ),
                const SizedBox(height: 4),
                TextField(
                    controller: code,
                    autocorrect: false,
                    textCapitalization: TextCapitalization.characters,
                    style: const TextStyle(fontFamily: mono),
                    decoration: const InputDecoration(labelText: 'One-time enrollment code', hintText: 'XXXXX-XXXXX')),
                const SizedBox(height: 12),
                TextField(
                    controller: sk,
                    autocorrect: false,
                    maxLines: 2,
                    minLines: 1,
                    style: const TextStyle(fontFamily: mono, fontSize: 13),
                    decoration: InputDecoration(
                        labelText: widget.firstRun ? 'Sync key' : 'Sync key (only if the server already has a vault)',
                        helperText: '52 characters, shown under Sync → Add device',
                        helperMaxLines: 2)),
                if (widget.firstRun) ...[const SizedBox(height: 12), PassphraseField(pass)],
                const SizedBox(height: 12),
                TextField(controller: name, decoration: const InputDecoration(labelText: 'Name for this device')),
                if (http) ...[
                  const SizedBox(height: 12),
                  WarningBox('Plain HTTP sends your device token unencrypted. Your vault contents stay encrypted, '
                      'but anyone on the network could use the token to read or overwrite the encrypted data. '
                      'Only allowed for addresses on your own network.'),
                  SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      value: insecure,
                      onChanged: (v) => setState(() {
                        insecure = v;
                        error = null;
                      }),
                      title: const Text('Allow insecure LAN sync')),
                ],
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton(onPressed: () => setState(() => advanced = !advanced), child: Text(advanced ? 'Hide advanced' : 'Advanced')),
                ),
                if (advanced)
                  TextField(
                      controller: pin,
                      autocorrect: false,
                      style: const TextStyle(fontFamily: mono, fontSize: 13),
                      decoration: const InputDecoration(
                          labelText: 'Certificate SHA-256 fingerprint (optional)',
                          helperText: 'For a self-signed or private-CA certificate. Hex, with or without colons.',
                          helperMaxLines: 2)),
                if (error != null)
                  Padding(padding: const EdgeInsets.only(top: 12), child: Text(error!, style: TextStyle(color: t.colorScheme.error))),
                const SizedBox(height: 20),
                FilledButton(
                  onPressed: busy ? null : _go,
                  child: busy
                      ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                      : Text(widget.firstRun ? 'Join' : 'Connect'),
                ),
              ]),
            ),
          ),
        ]),
      ),
    );
  }
}

class _ScanScreen extends StatefulWidget {
  const _ScanScreen();
  @override
  State<_ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<_ScanScreen> {
  bool done = false;
  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Scan enrollment QR')),
        body: MobileScanner(onDetect: (capture) {
          final v = capture.barcodes.isEmpty ? null : capture.barcodes.first.rawValue;
          if (v == null || done) return;
          done = true;
          Navigator.pop(context, v);
        }),
      );
}
