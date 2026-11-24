import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:sshsync_core/sshsync_core.dart';

import '../main.dart';
import '../platform.dart';
import '../services.dart';
import '../theme.dart';
import 'dialogs.dart';
import 'hosts.dart';
import 'onboarding.dart';

const _typeNames = {
  'host': 'Host',
  'credential': 'Credential',
  'group': 'Group',
  'known_host': 'Trusted host key',
  'setting': 'Setting',
  'conflict': 'Conflict note',
};

class SyncScreen extends StatefulWidget {
  const SyncScreen({super.key});
  @override
  State<SyncScreen> createState() => _SyncScreenState();
}

class _SyncScreenState extends State<SyncScreen> {
  Future<List<DeviceInfo>>? devices;

  App get app => App.i;
  SyncService get sync => app.sync;

  void _loadDevices() {
    if (sync.api != null) setState(() => devices = sync.api!.devices());
  }

  @override
  void initState() {
    super.initState();
    _loadDevices();
  }

  String _recordName(String id) {
    final r = app.store.get(id);
    if (r == null) return 'deleted item';
    return r.str('nickname', r.str('label', r.str('name', r.str('host', r.str('key', r.type)))));
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: app,
        builder: (context, _) {
          final scheme = Theme.of(context).colorScheme;
          final st = sync.status;
          final conflicts = app.conflicts;
          final pending = app.store.pendingSummary().where((p) => p.type != 'conflict' || !p.deleted).toList();
          Widget section(String s) => Padding(
              padding: const EdgeInsets.fromLTRB(4, 22, 4, 8),
              child: Text(s.toUpperCase(), style: Theme.of(context).textTheme.labelMedium?.copyWith(color: scheme.onSurfaceVariant, letterSpacing: 0.8)));

          final (IconData icon, Color color, String title) = !sync.configured
              ? (Icons.cloud_off, scheme.onSurfaceVariant, 'Sync is off')
              : switch (st?.phase) {
                  SyncPhase.syncing => (Icons.sync, scheme.secondary, 'Syncing…'),
                  SyncPhase.offline => (Icons.cloud_off, scheme.tertiary, 'Offline'),
                  SyncPhase.error => (Icons.error_outline, scheme.error, 'Sync problem'),
                  SyncPhase.revoked => (Icons.block, scheme.error, 'This device was revoked'),
                  _ => (Icons.cloud_done, scheme.primary, 'Up to date'),
                };

          return Scaffold(
            appBar: AppBar(title: const Text('Sync'), actions: [
              if (sync.configured)
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: FilledButton.tonalIcon(
                    icon: const Icon(Icons.sync, size: 18),
                    label: const Text('Sync now'),
                    onPressed: st?.phase == SyncPhase.syncing
                        ? null
                        : () async {
                            await sync.syncNow();
                            _loadDevices();
                          },
                  ),
                ),
            ]),
            body: ListView(padding: const EdgeInsets.fromLTRB(16, 4, 16, 40), children: [
              Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 640),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                          Row(children: [
                            Icon(icon, color: color),
                            const SizedBox(width: 10),
                            Text(title, style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
                          ]),
                          const SizedBox(height: 10),
                          if (!sync.configured)
                            const Text('Everything works without it. Connect a server you run to keep your devices in step. '
                                'The server only ever stores encrypted data.')
                          else ...[
                            SelectableText(sync.url ?? '', style: const TextStyle(fontFamily: mono, fontSize: 13)),
                            const SizedBox(height: 4),
                            Text('Last successful sync: ${timeAgo(st?.lastSuccessMs)}', style: TextStyle(color: scheme.onSurfaceVariant)),
                            if (st?.error != null && st?.phase != SyncPhase.idle)
                              Padding(padding: const EdgeInsets.only(top: 6), child: Text(st!.error!, style: TextStyle(color: color))),
                            if (st?.phase == SyncPhase.offline)
                              Padding(
                                  padding: const EdgeInsets.only(top: 6),
                                  child: Text('Keep working. Changes are saved here and sent when the server is reachable.',
                                      style: TextStyle(color: scheme.onSurfaceVariant))),
                          ],
                          if (sync.insecureLan) ...[
                            const SizedBox(height: 12),
                            const WarningBox('Syncing over plain HTTP. Your vault stays encrypted, but the device token is sent in the clear.'),
                          ],
                          if (st?.clockWarning ?? false) ...[
                            const SizedBox(height: 12),
                            WarningBox('This device\'s clock is ${(st!.clockSkewMs!.abs() / 60000).round()} minutes off the server\'s. '
                                'Fix the clock so "latest change wins" stays accurate.'),
                          ],
                          if ((st?.unreadable ?? 0) > 0) ...[
                            const SizedBox(height: 12),
                            WarningBox('${st!.unreadable} item(s) on the server could not be decrypted with this vault and were skipped.'),
                          ],
                          if (st?.keyslotUnreadable ?? false) ...[
                            const SizedBox(height: 12),
                            const WarningBox('The server\'s copy of the vault keyslot could not be opened with this device\'s sync key. '
                                'Hosts and keys still sync, but passphrase changes will not reach or leave this device, and new devices cannot join, until it is replaced.'),
                          ],
                          if (st?.phase == SyncPhase.revoked) ...[
                            const SizedBox(height: 12),
                            const WarningBox('Another device revoked this one. Local data is untouched. Disconnect, then enroll again or erase this device in Settings.'),
                          ],
                          const SizedBox(height: 14),
                          Wrap(spacing: 8, runSpacing: 8, children: [
                            if (!sync.configured)
                              FilledButton.icon(
                                icon: const Icon(Icons.link),
                                label: const Text('Connect to server'),
                                onPressed: () async {
                                  await Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const JoinScreen(firstRun: false)));
                                  _loadDevices();
                                },
                              )
                            else ...[
                              if (st?.phase != SyncPhase.revoked)
                                FilledButton.icon(
                                  icon: const Icon(Icons.qr_code_2),
                                  label: const Text('Add device'),
                                  onPressed: () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const InviteScreen())),
                                ),
                              OutlinedButton(
                                onPressed: () async {
                                  if (await confirm(context, 'Disconnect from server?',
                                      'This device stops syncing and is removed from the server\'s device list. Your data stays on this device.',
                                      action: 'Disconnect')) {
                                    await sync.disconnect();
                                    setState(() => devices = null);
                                  }
                                },
                                child: const Text('Disconnect'),
                              ),
                            ],
                          ]),
                        ]),
                      ),
                    ),
                    if (conflicts.isNotEmpty) ...[
                      section('Conflicts to review (${conflicts.length})'),
                      for (final c in conflicts) _ConflictCard(c, _recordName),
                    ],
                    if (sync.configured || pending.isNotEmpty) ...[
                      section('Waiting to upload (${pending.length})'),
                      if (pending.isEmpty)
                        Padding(padding: const EdgeInsets.symmetric(horizontal: 4), child: Text('Nothing pending.', style: TextStyle(color: scheme.onSurfaceVariant)))
                      else
                        Card(
                          child: Column(children: [
                            for (final p in pending.take(50))
                              ListTile(
                                dense: true,
                                leading: Icon(p.deleted ? Icons.delete_outline : Icons.edit_outlined, size: 20),
                                title: Text('${_typeNames[p.type] ?? p.type}: ${p.deleted ? 'deleted' : _recordName(p.id)}'),
                                subtitle: p.deleted || p.fields.isEmpty ? null : Text(p.fields.join(', '), style: const TextStyle(fontFamily: mono, fontSize: 11)),
                              ),
                            if (pending.length > 50) Padding(padding: const EdgeInsets.all(8), child: Text('and ${pending.length - 50} more')),
                          ]),
                        ),
                      if (!sync.configured && pending.isNotEmpty)
                        Padding(
                            padding: const EdgeInsets.fromLTRB(4, 8, 4, 0),
                            child: Text('These are sent once you connect a server.', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12))),
                    ],
                    if (sync.configured) ...[
                      section('Devices'),
                      FutureBuilder<List<DeviceInfo>>(
                        future: devices,
                        builder: (context, snap) {
                          if (snap.connectionState != ConnectionState.done) {
                            return const Padding(padding: EdgeInsets.all(16), child: Center(child: CircularProgressIndicator()));
                          }
                          if (snap.hasError || snap.data == null) {
                            return Padding(
                              padding: const EdgeInsets.symmetric(horizontal: 4),
                              child: Row(children: [
                                Expanded(child: Text('The device list needs the server to be reachable.', style: TextStyle(color: scheme.onSurfaceVariant))),
                                TextButton(onPressed: _loadDevices, child: const Text('Retry')),
                              ]),
                            );
                          }
                          return Card(
                            child: Column(children: [
                              for (final d in snap.data!)
                                ListTile(
                                  leading: Icon(d.platform == 'android' ? Icons.smartphone : Icons.computer, color: d.revoked ? scheme.onSurfaceVariant : null),
                                  title: Text('${d.name}${d.current ? '  (this device)' : ''}',
                                      style: TextStyle(decoration: d.revoked ? TextDecoration.lineThrough : null)),
                                  subtitle: Text(d.revoked ? 'Revoked' : 'Last seen ${timeAgo(d.lastSeenAt)}  ·  enrolled ${timeAgo(d.createdAt)}'),
                                  trailing: d.revoked || d.current
                                      ? null
                                      : TextButton(
                                          onPressed: () async {
                                            if (!await confirm(
                                                context,
                                                'Revoke ${d.name}?',
                                                'It can no longer sync. It still holds everything it already synced, including the vault key, '
                                                    'so if it is lost or stolen, change the passwords and keys it had.',
                                                action: 'Revoke',
                                                danger: true)) {
                                              return;
                                            }
                                            try {
                                              await sync.api!.revokeDevice(d.id);
                                            } catch (_) {
                                              if (context.mounted) toast(context, 'Could not reach the server.');
                                            }
                                            _loadDevices();
                                          },
                                          child: Text('Revoke', style: TextStyle(color: scheme.error)),
                                        ),
                                ),
                            ]),
                          );
                        },
                      ),
                      Align(
                        alignment: Alignment.centerLeft,
                        child: TextButton(
                          onPressed: () async {
                            try {
                              // The API saves the new token itself, before
                              // and after the server confirms it.
                              await sync.api!.rotateToken();
                              if (context.mounted) toast(context, 'This device now uses a new token.');
                            } catch (_) {
                              if (context.mounted) toast(context, 'Could not reach the server. Try again when it is reachable.');
                            }
                          },
                          child: const Text('Rotate this device\'s token'),
                        ),
                      ),
                    ],
                  ]),
                ),
              ),
            ]),
          );
        },
      );
}

class _ConflictCard extends StatelessWidget {
  final Rec c;
  final String Function(String id) nameOf;
  const _ConflictCard(this.c, this.nameOf);

  String _show(Object? v, bool secret) {
    if (v == null || v == '') return '(empty)';
    if (secret) return '•••••••• (hidden)';
    return v is String ? v : '$v';
  }

  @override
  Widget build(BuildContext context) {
    final app = App.i;
    final scheme = Theme.of(context).colorScheme;
    final type = c.str('record_type'), field = c.str('field');
    final secret = RecordType.isSecret(type, field);
    final isDelete = c.str('kind') == 'delete';
    final self = app.store.deviceId;
    String who(String key) => c.str(key) == self ? 'this device' : 'another device';
    final snapshot = (c.fields['snapshot'] as Map?)?.cast<String, dynamic>();
    final style = const TextStyle(fontFamily: mono, fontSize: 13);
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Card(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12), side: BorderSide(color: scheme.tertiary.withValues(alpha: 0.6))),
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Icon(Icons.call_split, size: 18, color: scheme.tertiary),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                    isDelete
                        ? '${_typeNames[type] ?? type} "${snapshot?['nickname'] ?? snapshot?['label'] ?? snapshot?['name'] ?? ''}" was deleted on one device and edited on another'
                        : '${_typeNames[type] ?? type} "${nameOf(c.str('record_id'))}" — $field changed on two devices',
                    style: const TextStyle(fontWeight: FontWeight.w600)),
              ),
            ]),
            const SizedBox(height: 10),
            if (isDelete)
              const Text('The delete was applied. You can bring the edited version back as a new item.')
            else ...[
              Text('Kept (${who('winning_device')}, ${timeAgo(c.integer('winning_at'))})', style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
              Text(_show(c.fields['winning_value'], secret), style: style),
              const SizedBox(height: 8),
              Text('Replaced (${who('losing_device')}, ${timeAgo(c.integer('losing_at'))})', style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
              Text(_show(c.fields['losing_value'], secret), style: style.copyWith(color: scheme.tertiary)),
            ],
            const SizedBox(height: 12),
            Wrap(spacing: 8, children: [
              if (isDelete)
                OutlinedButton(
                  onPressed: () {
                    if (snapshot != null) app.store.put(type, snapshot);
                    app.store.delete(c.id);
                  },
                  child: const Text('Restore edited version'),
                )
              else
                OutlinedButton(
                  onPressed: () {
                    if (app.store.get(c.str('record_id')) != null) {
                      app.store.update(c.str('record_id'), {field: c.fields['losing_value']});
                    }
                    app.store.delete(c.id);
                  },
                  child: const Text('Use the other value'),
                ),
              FilledButton.tonal(onPressed: () => app.store.delete(c.id), child: Text(isDelete ? 'Keep it deleted' : 'Keep current')),
            ]),
          ]),
        ),
      ),
    );
  }
}

/// Shows the QR and text another device needs to join.
class InviteScreen extends StatefulWidget {
  const InviteScreen({super.key});
  @override
  State<InviteScreen> createState() => _InviteScreenState();
}

class _InviteScreenState extends State<InviteScreen> {
  late final invite = App.i.sync.invite();
  @override
  Widget build(BuildContext context) => Secure(
        child: Scaffold(
          appBar: AppBar(title: const Text('Add device')),
          body: FutureBuilder(
            future: invite,
            builder: (context, snap) {
              if (snap.connectionState != ConnectionState.done) return const Center(child: CircularProgressIndicator());
              final v = snap.data;
              if (v == null) {
                return const Center(child: Padding(padding: EdgeInsets.all(24), child: Text('The server must be reachable to add a device.')));
              }
              final scheme = Theme.of(context).colorScheme;
              return ListView(padding: const EdgeInsets.all(20), children: [
                Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 440),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                      const Text('On the new device choose "I already have a vault on another device", then scan this code '
                          'or enter the three values below. You will also need your master passphrase.'),
                      const SizedBox(height: 16),
                      Center(
                        child: Container(
                          color: Colors.white,
                          padding: const EdgeInsets.all(12),
                          child: QrImageView(data: v.payload, size: 260, backgroundColor: Colors.white),
                        ),
                      ),
                      const SizedBox(height: 16),
                      const WarningBox('This contains your sync key. Show it only to your own devices. The code works once and expires in 10 minutes.'),
                      const SizedBox(height: 16),
                      _kv(context, 'Server', App.i.sync.url ?? ''),
                      _kv(context, 'One-time code', v.code),
                      _kv(context, 'Sync key', v.syncKey),
                      const SizedBox(height: 12),
                      OutlinedButton.icon(
                        icon: const Icon(Icons.copy),
                        label: const Text('Copy enrollment text'),
                        onPressed: () {
                          Native.copySecret(v.payload);
                          toast(context, 'Copied. The clipboard is cleared in 30 seconds.');
                        },
                      ),
                      const SizedBox(height: 8),
                      Text('Keep a copy of the sync key with your backup: without it, a new device cannot join.',
                          style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12)),
                    ]),
                  ),
                ),
              ]);
            },
          ),
        ),
      );

  Widget _kv(BuildContext context, String k, String v) => Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(k, style: Theme.of(context).textTheme.labelMedium?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant)),
          Row(children: [
            Expanded(child: SelectableText(v, style: const TextStyle(fontFamily: mono, fontSize: 13))),
            IconButton(
                tooltip: 'Copy $k',
                icon: const Icon(Icons.copy, size: 18),
                onPressed: () {
                  k == 'Server' ? Clipboard.setData(ClipboardData(text: v)) : Native.copySecret(v);
                  toast(context, '$k copied');
                }),
          ]),
        ]),
      );
}
