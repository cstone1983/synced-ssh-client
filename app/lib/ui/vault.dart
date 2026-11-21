import 'dart:isolate';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:sshsync_core/sshsync_core.dart';

import '../main.dart';
import '../platform.dart';
import '../services.dart';
import '../theme.dart';
import 'dialogs.dart';

/// Credentials list.
class VaultScreen extends StatelessWidget {
  const VaultScreen({super.key});
  @override
  Widget build(BuildContext context) => Secure(
        child: ListenableBuilder(
          listenable: App.i,
          builder: (context, _) {
            final app = App.i;
            final scheme = Theme.of(context).colorScheme;
            final creds = app.credentials;
            return Scaffold(
              appBar: AppBar(title: const Text('Vault'), actions: [
                IconButton(tooltip: 'Lock now', icon: const Icon(Icons.lock_outline), onPressed: app.lock),
              ]),
              floatingActionButton: FloatingActionButton.extended(
                icon: const Icon(Icons.add),
                label: const Text('Credential'),
                onPressed: () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const CredentialEditor())),
              ),
              body: creds.isEmpty
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: Text('No credentials yet.\nA credential is a username with a password, a key, or both. Hosts share them.',
                            textAlign: TextAlign.center, style: TextStyle(color: scheme.onSurfaceVariant)),
                      ),
                    )
                  : ListView(padding: const EdgeInsets.only(bottom: 88), children: [
                      for (final c in creds)
                        ListTile(
                          leading: Icon(c.get<String>('public_key') != null ? Icons.key : Icons.password, color: scheme.primary),
                          title: Text(c.str('label', c.str('username'))),
                          subtitle: Text(
                            [
                              c.str('username'),
                              if (c.get<String>('public_key') != null) c.str('key_type'),
                              if (c.get<String>('password') != null) 'password',
                              if (c.flag('prompt_password')) 'asks for password',
                              '${app.hosts.where((h) => h.get<String>('credential_id') == c.id).length} hosts',
                            ].join('  ·  '),
                            style: const TextStyle(fontFamily: mono, fontSize: 12),
                          ),
                          trailing: const Icon(Icons.chevron_right),
                          onTap: () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => CredentialEditor(credential: c))),
                        ),
                    ]),
            );
          },
        ),
      );
}

/// Create or edit a credential: username + password and/or key.
/// Pops with the record id when saved.
class CredentialEditor extends StatefulWidget {
  final Rec? credential;
  const CredentialEditor({super.key, this.credential});
  @override
  State<CredentialEditor> createState() => _CredentialEditorState();
}

class _CredentialEditorState extends State<CredentialEditor> {
  late final c = widget.credential;
  late final label = TextEditingController(text: c?.str('label'));
  late final user = TextEditingController(text: c?.str('username'));
  late final pass = TextEditingController(text: c?.get<String>('password'));
  late bool prompt = c?.flag('prompt_password') ?? false;
  late String? privateKey = c?.get<String>('private_key');
  late String? publicKey = c?.get<String>('public_key');
  late String? keyType = c?.get<String>('key_type');
  late String? fingerprint = c?.get<String>('key_fingerprint');
  bool hidden = true, busy = false;
  String? error;

  App get app => App.i;

  void _setKey(KeyInfo? k) => setState(() {
        privateKey = k?.privatePem;
        publicKey = k?.publicLine;
        keyType = k?.type;
        fingerprint = k?.fingerprint;
      });

  String? _save() {
    if (user.text.trim().isEmpty) {
      setState(() => error = 'Enter a username.');
      return null;
    }
    final data = {
      'label': label.text.trim().isEmpty ? user.text.trim() : label.text.trim(),
      'username': user.text.trim(),
      'prompt_password': prompt,
      'password': prompt || pass.text.isEmpty ? null : pass.text,
      'private_key': privateKey,
      'public_key': publicKey,
      'key_type': keyType,
      'key_fingerprint': fingerprint,
    };
    return c == null ? app.store.put(RecordType.credential, data) : (app.store..update(c!.id, data)).let(c!.id);
  }

  Future<void> _generate(bool rsa) async {
    setState(() => busy = true);
    try {
      final comment = '${user.text.trim().isEmpty ? 'sshsync' : user.text.trim()}@sshsync';
      _setKey(rsa ? await Keys.generateRsa(bits: 4096, comment: comment) : Keys.generateEd25519(app.crypto, comment: comment));
    } catch (_) {
      if (mounted) toast(context, 'Key generation failed.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _import({String? pasted}) async {
    String? text = pasted;
    if (text == null) {
      final bytes = await pickFileBytes();
      if (bytes == null) return;
      text = String.fromCharCodes(bytes);
    }
    String? passphrase;
    if (!mounted) return;
    try {
      if (Keys.needsPassphrase(text)) {
        passphrase = await askText(context, 'Key passphrase',
            body: 'The key is decrypted once and then protected by your vault instead.', label: 'Passphrase', secret: true);
        if (passphrase == null) return;
      }
      setState(() => busy = true);
      final t = text, p = passphrase;
      // Decrypting can take a second; keep the UI responsive.
      final k = await Isolate.run(() => Keys.import(t, passphrase: p));
      _setKey(k);
    } on KeyImportException catch (e) {
      if (mounted) toast(context, e.wrongPassphrase ? 'Wrong passphrase for that key.' : e.message);
    } catch (_) {
      if (mounted) toast(context, 'That file could not be read as a private key.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  /// ssh-copy-id: log in with the password once and add the public key.
  Future<void> _install() async {
    if (_save() == null) return;
    final hosts = app.hosts.where((h) => h.get<String>('credential_id') == c?.id).toList();
    if (hosts.isEmpty) return toast(context, 'No host uses this credential yet. Link it to a host first.');
    final host = hosts.length == 1
        ? hosts.first
        : await showDialog<Rec>(
            context: context,
            builder: (d) => SimpleDialog(title: const Text('Install key on'), children: [
              for (final h in hosts) SimpleDialogOption(onPressed: () => Navigator.pop(d, h), child: Text(h.str('nickname'))),
            ]),
          );
    if (host == null || !mounted) return;
    setState(() => busy = true);
    try {
      final fresh = app.store.get(host.id)!;
      final base = ConnectSpec.fromHost(app.store, fresh);
      final spec = ConnectSpec(
          label: base.label,
          host: base.host,
          port: base.port,
          username: base.username,
          authOrder: AuthOrder.passwordOnly,
          password: base.password,
          legacyAlgorithms: base.legacyAlgorithms,
          jump: base.jump);
      final conn = await sshConnect(spec, app.sessions.knownHosts, app.sessions.prompts);
      try {
        await installPublicKey(conn.client, publicKey!);
      } finally {
        conn.close();
      }
      // Prove the key works before offering to rely on it.
      final check = await sshConnect(
          ConnectSpec(
              label: base.label,
              host: base.host,
              port: base.port,
              username: base.username,
              authOrder: AuthOrder.keyOnly,
              privateKeyPem: privateKey,
              legacyAlgorithms: base.legacyAlgorithms,
              jump: base.jump),
          app.sessions.knownHosts,
          app.sessions.prompts);
      check.close();
      if (!mounted) return;
      if (await confirm(context, 'Key installed', 'Logging in to ${base.label} with the key works. Switch this host to "Key only"?',
          action: 'Switch to key only')) {
        app.store.update(host.id, {'auth_order': AuthOrder.keyOnly});
      }
    } on SshFailure catch (e) {
      if (mounted) toast(context, 'Could not install the key: ${e.message}');
    } catch (_) {
      if (mounted) toast(context, 'Could not install the key.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final used = c == null ? 0 : app.hosts.where((h) => h.get<String>('credential_id') == c!.id).length;
    Widget label_(String s) => Padding(
        padding: const EdgeInsets.only(top: 22, bottom: 8),
        child: Text(s.toUpperCase(), style: Theme.of(context).textTheme.labelMedium?.copyWith(color: scheme.onSurfaceVariant, letterSpacing: 0.8)));
    return Secure(
      child: Scaffold(
        appBar: AppBar(
          title: Text(c == null ? 'New credential' : 'Edit credential'),
          actions: [
            if (c != null)
              IconButton(
                tooltip: 'Delete',
                icon: const Icon(Icons.delete_outline),
                onPressed: () async {
                  if (await confirm(context, 'Delete credential?',
                      used == 0 ? 'This cannot be undone.' : '$used host${used == 1 ? '' : 's'} use it and will be left without a login.',
                      action: 'Delete', danger: true)) {
                    app.store.delete(c!.id);
                    if (context.mounted) Navigator.pop(context);
                  }
                },
              ),
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: FilledButton(
                  onPressed: busy
                      ? null
                      : () {
                          final id = _save();
                          if (id != null) Navigator.pop(context, id);
                        },
                  child: const Text('Save')),
            ),
          ],
        ),
        body: ListView(padding: const EdgeInsets.fromLTRB(20, 4, 20, 40), children: [
          Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                if (busy) const LinearProgressIndicator(),
                if (error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(error!, style: TextStyle(color: scheme.error))),
                label_('Identity'),
                TextField(controller: label, decoration: const InputDecoration(labelText: 'Label', hintText: 'e.g. Homelab root')),
                const SizedBox(height: 14),
                TextField(controller: user, autocorrect: false, style: const TextStyle(fontFamily: mono), decoration: const InputDecoration(labelText: 'Username')),
                if (used > 0)
                  Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Text('Used by $used host${used == 1 ? '' : 's'}. Changes apply to all of them.', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12))),
                label_('Password'),
                SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Ask every time'),
                    subtitle: const Text('Do not store a password'),
                    value: prompt,
                    onChanged: (v) => setState(() => prompt = v)),
                if (!prompt)
                  TextField(
                    controller: pass,
                    obscureText: hidden,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: InputDecoration(
                      labelText: 'Password (optional)',
                      suffixIcon: Row(mainAxisSize: MainAxisSize.min, children: [
                        IconButton(
                            tooltip: hidden ? 'Show' : 'Hide',
                            icon: Icon(hidden ? Icons.visibility : Icons.visibility_off),
                            onPressed: () => setState(() => hidden = !hidden)),
                        IconButton(
                            tooltip: 'Copy (cleared after 30 s)',
                            icon: const Icon(Icons.copy),
                            onPressed: pass.text.isEmpty
                                ? null
                                : () {
                                    Native.copySecret(pass.text);
                                    toast(context, 'Password copied. The clipboard is cleared in 30 seconds.');
                                  }),
                      ]),
                    ),
                    onChanged: (_) => setState(() {}),
                  ),
                label_('Private key'),
                if (publicKey == null) ...[
                  Text('No key. Generate one here, or import an OpenSSH or PuTTY (.ppk) key.', style: TextStyle(color: scheme.onSurfaceVariant)),
                  const SizedBox(height: 12),
                  Wrap(spacing: 8, runSpacing: 8, children: [
                    FilledButton.tonalIcon(onPressed: busy ? null : () => _generate(false), icon: const Icon(Icons.auto_awesome), label: const Text('Generate Ed25519')),
                    OutlinedButton(onPressed: busy ? null : () => _generate(true), child: const Text('Generate RSA 4096')),
                    OutlinedButton.icon(onPressed: busy ? null : _import, icon: const Icon(Icons.file_open_outlined), label: const Text('Import file')),
                    OutlinedButton.icon(
                      onPressed: busy
                          ? null
                          : () async {
                              final data = await Clipboard.getData(Clipboard.kTextPlain);
                              final t = data?.text ?? '';
                              if (!t.contains('PRIVATE KEY') && !t.contains('PuTTY-User-Key-File')) {
                                if (context.mounted) toast(context, 'The clipboard does not contain a private key.');
                                return;
                              }
                              _import(pasted: t);
                            },
                      icon: const Icon(Icons.content_paste),
                      label: const Text('Paste key'),
                    ),
                  ]),
                  if (busy) Padding(padding: const EdgeInsets.only(top: 8), child: Text('Working… RSA 4096 can take up to a minute on a phone.', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12))),
                ] else ...[
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(14),
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Row(children: [
                          Icon(Icons.key, size: 18, color: scheme.primary),
                          const SizedBox(width: 8),
                          Text(keyType ?? 'key', style: const TextStyle(fontFamily: mono, fontWeight: FontWeight.w600)),
                        ]),
                        const SizedBox(height: 8),
                        SelectableText(fingerprint ?? '', style: TextStyle(fontFamily: mono, fontSize: 12, color: scheme.onSurfaceVariant)),
                        const SizedBox(height: 12),
                        Wrap(spacing: 8, runSpacing: 8, children: [
                          OutlinedButton.icon(
                            icon: const Icon(Icons.copy, size: 18),
                            label: const Text('Copy public key'),
                            onPressed: () {
                              Clipboard.setData(ClipboardData(text: publicKey!));
                              toast(context, 'Public key copied');
                            },
                          ),
                          OutlinedButton.icon(
                            icon: const Icon(Icons.save_alt, size: 18),
                            label: const Text('Export public key'),
                            onPressed: () async {
                              try {
                                await FilePicker.saveFile(
                                    fileName: 'id_${(keyType ?? 'key').replaceAll('ssh-', '')}.pub',
                                    bytes: Uint8List.fromList('${publicKey!}\n'.codeUnits));
                              } catch (_) {
                                if (context.mounted) toast(context, 'Could not save the file.');
                              }
                            },
                          ),
                          if (c != null)
                            FilledButton.tonalIcon(
                                icon: const Icon(Icons.upload, size: 18), label: const Text('Install on server'), onPressed: busy ? null : _install),
                          TextButton(
                            onPressed: () async {
                              if (await confirm(context, 'Remove key?', 'The private key is erased from this credential on all devices.',
                                  action: 'Remove', danger: true)) {
                                _setKey(null);
                              }
                            },
                            child: Text('Remove', style: TextStyle(color: scheme.error)),
                          ),
                        ]),
                        if (c == null)
                          Padding(
                              padding: const EdgeInsets.only(top: 8),
                              child: Text('Save first to install the key on a server.', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12))),
                      ]),
                    ),
                  ),
                ],
              ]),
            ),
          ),
        ]),
      ),
    );
  }
}

extension _Let<T> on T {
  R let<R>(R value) => value;
}
