import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:sshsync_core/sshsync_core.dart';

import '../theme.dart';

/// Lets the user pick one file and returns its bytes (null if cancelled).
Future<Uint8List?> pickFileBytes() async {
  final f = await FilePicker.pickFile();
  return f == null ? null : await f.xFile.readAsBytes();
}

void toast(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message)));
}

Future<bool> confirm(BuildContext context, String title, String body,
    {String action = 'OK', bool danger = false}) async {
  final r = await showDialog<bool>(
    context: context,
    builder: (c) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: [
        TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
        FilledButton(
          style: danger
              ? FilledButton.styleFrom(
                  backgroundColor: Theme.of(c).colorScheme.error,
                  foregroundColor: Theme.of(c).colorScheme.onError)
              : null,
          onPressed: () => Navigator.pop(c, true),
          child: Text(action),
        ),
      ],
    ),
  );
  return r ?? false;
}

/// Asks for one line of text. Returns null if cancelled.
Future<String?> askText(BuildContext context, String title,
    {String? label, String? body, bool secret = false, String initial = '', String action = 'OK'}) {
  final ctl = TextEditingController(text: initial);
  var hidden = secret;
  return showDialog<String>(
    context: context,
    builder: (c) => StatefulBuilder(
      builder: (c, setState) => AlertDialog(
        title: Text(title),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (body != null) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(body)),
          TextField(
            controller: ctl,
            autofocus: true,
            obscureText: hidden,
            autocorrect: !secret,
            enableSuggestions: !secret,
            decoration: InputDecoration(
              labelText: label,
              suffixIcon: secret
                  ? IconButton(
                      tooltip: hidden ? 'Show' : 'Hide',
                      icon: Icon(hidden ? Icons.visibility : Icons.visibility_off),
                      onPressed: () => setState(() => hidden = !hidden))
                  : null,
            ),
            onSubmitted: (v) => Navigator.pop(c, v),
          ),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, ctl.text), child: Text(action)),
        ],
      ),
    ),
  );
}

/// Shows the questions an SSH connection needs answered.
class DialogPrompts implements SshPrompts {
  final GlobalKey<NavigatorState> nav;
  DialogPrompts(this.nav);

  BuildContext? get _ctx => nav.currentContext;

  @override
  Future<bool> confirmHostKey(HostKeyQuestion q) async {
    final ctx = _ctx;
    if (ctx == null) return false;
    final r = await showDialog<bool>(
      context: ctx,
      barrierDismissible: false,
      builder: (c) {
        final scheme = Theme.of(c).colorScheme;
        Widget fp(String label, String value, Color color) => Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(label, style: Theme.of(c).textTheme.labelMedium?.copyWith(color: scheme.onSurfaceVariant)),
                const SizedBox(height: 4),
                SelectableText(value, style: TextStyle(fontFamily: mono, fontSize: 13, color: color)),
              ]),
            );
        if (!q.changed) {
          return AlertDialog(
            icon: Icon(Icons.fingerprint, color: scheme.secondary),
            title: const Text('Trust this host?'),
            content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('First connection to ${q.host}:${q.port}. Check the fingerprint against the server if you can.'),
              fp('${q.keyType} fingerprint', q.fingerprint, scheme.onSurface),
            ]),
            actions: [
              TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
              FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Trust and connect')),
            ],
          );
        }
        return AlertDialog(
          icon: Icon(Icons.gpp_bad, color: scheme.error, size: 36),
          title: const Text('Host key has changed'),
          content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('${q.host}:${q.port} is presenting a different key than the one you trusted. '
                'Unless you reinstalled this server or changed its keys, someone may be intercepting the connection.'),
            fp('Trusted', q.previousFingerprint!, scheme.onSurfaceVariant),
            fp('Presented now', q.fingerprint, scheme.error),
          ]),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(c, true),
                child: Text('Replace key and connect', style: TextStyle(color: scheme.error))),
            FilledButton(autofocus: true, onPressed: () => Navigator.pop(c, false), child: const Text('Do not connect')),
          ],
        );
      },
    );
    return r ?? false;
  }

  @override
  Future<String?> password(String label, {required bool retry}) async {
    final ctx = _ctx;
    if (ctx == null) return null;
    return askText(ctx, 'Password for $label',
        label: 'Password', secret: true, action: 'Connect',
        body: retry ? 'That password was not accepted. Try again.' : null);
  }

  @override
  Future<List<String>?> keyboardInteractive(String label, String instruction, List<InteractivePrompt> prompts) async {
    final ctx = _ctx;
    if (ctx == null) return null;
    final ctls = [for (final _ in prompts) TextEditingController()];
    return showDialog<List<String>>(
      context: ctx,
      barrierDismissible: false,
      builder: (c) => AlertDialog(
        title: Text('Sign in to $label'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (instruction.trim().isNotEmpty) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(instruction)),
          for (var i = 0; i < prompts.length; i++)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: TextField(
                controller: ctls[i],
                autofocus: i == 0,
                obscureText: !prompts[i].echo,
                decoration: InputDecoration(labelText: prompts[i].text.trim().replaceAll(RegExp(r':$'), '')),
              ),
            ),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, [for (final t in ctls) t.text]), child: const Text('Continue')),
        ],
      ),
    );
  }
}
