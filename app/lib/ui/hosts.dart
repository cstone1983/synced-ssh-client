import 'dart:io';

import 'package:flutter/material.dart';
import 'package:sshsync_core/sshsync_core.dart';
import 'package:win32_registry/win32_registry.dart';

import '../services.dart';
import '../theme.dart';
import 'dialogs.dart';
import 'terminal.dart';
import 'vault.dart';

String hostAddress(Rec h) {
  final user = App.i.store.get(h.get<String>('credential_id'))?.str('username') ?? '';
  final port = h.integer('port', 22);
  return '${user.isEmpty ? '' : '$user@'}${h.str('hostname')}${port == 22 ? '' : ':$port'}';
}

String timeAgo(int? ms) {
  if (ms == null || ms == 0) return 'never';
  final d = DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(ms));
  if (d.inMinutes < 1) return 'just now';
  if (d.inHours < 1) return '${d.inMinutes} min ago';
  if (d.inDays < 1) return '${d.inHours} h ago';
  if (d.inDays < 30) return '${d.inDays} d ago';
  final t = DateTime.fromMillisecondsSinceEpoch(ms);
  return '${t.year}-${t.month.toString().padLeft(2, '0')}-${t.day.toString().padLeft(2, '0')}';
}

/// Host list with quick connect, search, groups and bulk actions.
class HostsPane extends StatefulWidget {
  /// Called after a session is opened, so the shell can show it.
  final VoidCallback onConnected;
  final FocusNode? quickFocus;
  const HostsPane({super.key, required this.onConnected, this.quickFocus});
  @override
  State<HostsPane> createState() => _HostsPaneState();
}

class _HostsPaneState extends State<HostsPane> {
  final quick = TextEditingController(), search = TextEditingController();
  bool byLastUsed = false;
  Set<String>? selected; // non-null = selection mode
  final collapsed = <String>{};

  App get app => App.i;

  void _open(Rec host) {
    if (selected != null) {
      setState(() => selected!.contains(host.id) ? selected!.remove(host.id) : selected!.add(host.id));
      return;
    }
    final existing = app.sessions.sessions.where((s) => s.hostId == host.id && s.state != SessionState.disconnected);
    final s = existing.isNotEmpty ? existing.first : app.connect(host);
    currentSession.value = s.id;
    widget.onConnected();
  }

  Future<void> _quickConnect() async {
    final t = parseQuickConnect(quick.text);
    if (t == null) return toast(context, 'Type it as user@host or user@host:port');
    var user = t.user;
    if (user == null || user.isEmpty) {
      user = await askText(context, 'Username for ${t.host}', label: 'Username');
      if (user == null || user.trim().isEmpty) return;
      user = user.trim();
    }
    final s = app.sessions.open(ConnectSpec(
        label: t.host, host: t.host, port: t.port, username: user, keepaliveSeconds: app.setting<int>('keepalive')));
    quick.clear();
    currentSession.value = s.id;
    widget.onConnected();
    if (!mounted) return;
    final messenger = ScaffoldMessenger.of(context);
    final target = t, username = user;
    messenger.showSnackBar(SnackBar(
      duration: const Duration(seconds: 12),
      content: Text('Connecting to ${t.host}'),
      action: SnackBarAction(
        label: 'Save this host',
        onPressed: () {
          final existing = app.credentials.where((c) => c.str('username') == username && c.get<String>('password') == null && c.get<String>('private_key') == null);
          final cred = existing.isNotEmpty
              ? existing.first.id
              : app.store.put(RecordType.credential, {'label': username, 'username': username, 'prompt_password': true});
          app.store.put(RecordType.host, {
            'nickname': target.host,
            'hostname': target.host,
            'port': target.port,
            'credential_id': cred,
            'auth_order': AuthOrder.keyThenPassword,
            'tags': <String>[],
          });
          messenger.showSnackBar(SnackBar(content: Text('Saved ${target.host}')));
        },
      ),
    ));
  }

  Future<void> _menu(Rec h, Offset at) async {
    final v = await showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(at.dx, at.dy, at.dx, at.dy),
      items: const [
        PopupMenuItem(value: 'new', child: Text('Connect in new tab')),
        PopupMenuItem(value: 'edit', child: Text('Edit')),
        PopupMenuItem(value: 'dup', child: Text('Duplicate')),
        PopupMenuItem(value: 'pin', child: Text('Pin / unpin')),
        PopupMenuItem(value: 'select', child: Text('Select…')),
        PopupMenuItem(value: 'del', child: Text('Delete')),
      ],
    );
    if (!mounted || v == null) return;
    switch (v) {
      case 'new':
        currentSession.value = app.connect(h).id;
        widget.onConnected();
      case 'edit':
        Navigator.push(context, MaterialPageRoute<void>(builder: (_) => HostEditor(host: h)));
      case 'dup':
        app.store.put(RecordType.host, {...h.fields, 'nickname': '${h.str('nickname')} (copy)', 'pinned': false});
      case 'pin':
        app.store.update(h.id, {'pinned': !h.flag('pinned')});
      case 'select':
        setState(() => selected = {h.id});
      case 'del':
        if (await confirm(context, 'Delete ${h.str('nickname')}?', 'It is removed from all your devices at the next sync.',
            action: 'Delete', danger: true)) {
          app.store.delete(h.id);
        }
    }
  }

  Future<void> _assignCredential() async {
    final ids = selected!;
    final cred = await showDialog<String>(
      context: context,
      builder: (c) => SimpleDialog(title: Text('Credential for ${ids.length} host${ids.length == 1 ? '' : 's'}'), children: [
        for (final r in app.credentials)
          SimpleDialogOption(
              onPressed: () => Navigator.pop(c, r.id),
              child: ListTile(contentPadding: EdgeInsets.zero, title: Text(r.str('label')), subtitle: Text(r.str('username')))),
        if (app.credentials.isEmpty) const Padding(padding: EdgeInsets.all(24), child: Text('No credentials yet. Add one in the Vault.')),
      ]),
    );
    if (cred == null) return;
    for (final id in ids) {
      app.store.update(id, {'credential_id': cred});
    }
    setState(() => selected = null);
  }

  Future<void> _importSshConfig() async {
    final bytes = await pickFileBytes();
    if (bytes == null || !mounted) return;
    final items = parseSshConfig(String.fromCharCodes(bytes));
    final n = app.importHosts(items);
    toast(context, n == 0 ? 'No new hosts found (${items.length} already present or none in file).' : 'Imported $n host${n == 1 ? '' : 's'}.');
  }

  Future<void> _importPutty() async {
    final items = <ImportedHost>[];
    try {
      final root = CURRENT_USER.open(r'Software\SimonTatham\PuTTY\Sessions');
      for (final name in root.keys) {
        final k = root.open(name);
        final h = fromPuttySession(name, {
          'HostName': k.getString('HostName'),
          'PortNumber': k.getInt('PortNumber'),
          'UserName': k.getString('UserName'),
          'PublicKeyFile': k.getString('PublicKeyFile'),
          'Protocol': k.getString('Protocol'),
        });
        k.close();
        if (h != null) items.add(h);
      }
      root.close();
    } catch (_) {
      if (mounted) toast(context, 'No PuTTY sessions found in the registry.');
      return;
    }
    // Import each referenced .ppk as a credential so hosts can link to it.
    var keys = 0;
    for (final h in items) {
      final path = h.identityFile;
      if (path == null || path.isEmpty || h.user == null) continue;
      if (app.credentials.any((c) => c.str('username') == h.user && c.get<String>('private_key') != null)) continue;
      try {
        final text = File(path).readAsStringSync();
        String? pass;
        if (Keys.needsPassphrase(text)) {
          if (!mounted) return;
          pass = await askText(context, 'Passphrase for ${path.split(RegExp(r'[\\/]')).last}', secret: true, label: 'Key passphrase');
          if (pass == null) continue;
        }
        final key = Keys.import(text, passphrase: pass);
        app.store.put(RecordType.credential, {
          'label': '${h.user} (PuTTY key)',
          'username': h.user,
          'private_key': key.privatePem,
          'public_key': key.publicLine,
          'key_type': key.type,
          'key_fingerprint': key.fingerprint,
        });
        keys++;
      } catch (_) {}
    }
    final n = app.importHosts(items);
    if (mounted) toast(context, 'Imported $n host${n == 1 ? '' : 's'}${keys > 0 ? ' and $keys key${keys == 1 ? '' : 's'}' : ''} from PuTTY.');
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final q = search.text.trim().toLowerCase();
    final groups = {for (final g in app.groups) g.id: g};
    var hosts = app.hosts.where((h) {
      if (q.isEmpty) return true;
      final hay = [h.str('nickname'), h.str('hostname'), hostAddress(h), ...h.list<String>('tags'), groups[h.get<String>('group_id')]?.str('name') ?? '']
          .join(' ')
          .toLowerCase();
      return q.split(RegExp(r'\s+')).every(hay.contains);
    }).toList();
    int last(Rec h) => (app.sessions.hostState(h.id)['last_connected_at'] as int?) ?? 0;
    hosts.sort((a, b) => byLastUsed
        ? last(b).compareTo(last(a))
        : a.str('nickname').toLowerCase().compareTo(b.str('nickname').toLowerCase()));

    final sections = <(String, String, List<Rec>)>[];
    final pinned = hosts.where((h) => h.flag('pinned')).toList();
    if (pinned.isNotEmpty) sections.add(('__pinned', 'Pinned', pinned));
    for (final g in app.groups) {
      final list = hosts.where((h) => h.get<String>('group_id') == g.id && !h.flag('pinned')).toList();
      if (list.isNotEmpty) sections.add((g.id, g.str('name'), list));
    }
    final loose = hosts.where((h) => !groups.containsKey(h.get<String>('group_id')) && !h.flag('pinned')).toList();
    if (loose.isNotEmpty) sections.add(('__none', sections.isEmpty ? 'Hosts' : 'Ungrouped', loose));

    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 0),
        child: selected != null
            ? Row(children: [
                IconButton(tooltip: 'Cancel selection', icon: const Icon(Icons.close), onPressed: () => setState(() => selected = null)),
                Expanded(child: Text('${selected!.length} selected')),
                TextButton(onPressed: () => setState(() => selected = {for (final h in hosts) h.id}), child: const Text('All')),
                FilledButton.tonal(onPressed: selected!.isEmpty ? null : _assignCredential, child: const Text('Assign credential')),
              ])
            : Column(children: [
                TextField(
                  controller: quick,
                  focusNode: widget.quickFocus,
                  autocorrect: false,
                  keyboardType: TextInputType.url,
                  style: const TextStyle(fontFamily: mono, fontSize: 14),
                  onSubmitted: (_) => _quickConnect(),
                  decoration: InputDecoration(
                    hintText: 'user@host:port',
                    prefixIcon: const Icon(Icons.bolt),
                    labelText: 'Quick connect',
                    suffixIcon: IconButton(tooltip: 'Connect', icon: const Icon(Icons.arrow_forward), onPressed: _quickConnect),
                  ),
                ),
                const SizedBox(height: 8),
                Row(children: [
                  Expanded(
                    child: TextField(
                      controller: search,
                      onChanged: (_) => setState(() {}),
                      decoration: InputDecoration(
                        hintText: 'Search hosts, tags, users',
                        prefixIcon: const Icon(Icons.search),
                        isDense: true,
                        suffixIcon: search.text.isEmpty
                            ? null
                            : IconButton(tooltip: 'Clear', icon: const Icon(Icons.clear), onPressed: () => setState(search.clear)),
                      ),
                    ),
                  ),
                  PopupMenuButton<String>(
                    tooltip: 'Sort and import',
                    icon: const Icon(Icons.more_vert),
                    onSelected: (v) {
                      switch (v) {
                        case 'name':
                          setState(() => byLastUsed = false);
                        case 'last':
                          setState(() => byLastUsed = true);
                        case 'select':
                          setState(() => selected = {});
                        case 'groups':
                          Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const GroupsScreen()));
                        case 'ssh_config':
                          _importSshConfig();
                        case 'putty':
                          _importPutty();
                      }
                    },
                    itemBuilder: (_) => [
                      CheckedPopupMenuItem(value: 'name', checked: !byLastUsed, child: const Text('Sort by name')),
                      CheckedPopupMenuItem(value: 'last', checked: byLastUsed, child: const Text('Sort by last used')),
                      const PopupMenuDivider(),
                      const PopupMenuItem(value: 'select', child: Text('Select hosts…')),
                      const PopupMenuItem(value: 'groups', child: Text('Manage groups')),
                      const PopupMenuItem(value: 'ssh_config', child: Text('Import ssh_config file')),
                      if (Platform.isWindows) const PopupMenuItem(value: 'putty', child: Text('Import from PuTTY')),
                    ],
                  ),
                ]),
              ]),
      ),
      Expanded(
        child: sections.isEmpty
            ? Center(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Text(q.isEmpty ? 'No hosts yet.\nAdd one with +, or import an ssh_config file from the menu.' : 'Nothing matches "$q".',
                      textAlign: TextAlign.center, style: TextStyle(color: scheme.onSurfaceVariant)),
                ),
              )
            : ListView(padding: const EdgeInsets.only(bottom: 88, top: 4), children: [
                for (final (id, title, list) in sections) ...[
                  InkWell(
                    onTap: () => setState(() => collapsed.contains(id) ? collapsed.remove(id) : collapsed.add(id)),
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(16, 14, 12, 6),
                      child: Row(children: [
                        Expanded(
                          child: Text('${title.toUpperCase()}  ·  ${list.length}',
                              style: Theme.of(context).textTheme.labelMedium?.copyWith(color: scheme.onSurfaceVariant, letterSpacing: 0.8)),
                        ),
                        Icon(collapsed.contains(id) ? Icons.expand_more : Icons.expand_less, size: 18, color: scheme.onSurfaceVariant),
                      ]),
                    ),
                  ),
                  if (!collapsed.contains(id))
                    for (final h in list) _HostTile(h, selected: selected?.contains(h.id), onTap: () => _open(h), onMenu: (at) => _menu(h, at)),
                ],
              ]),
      ),
    ]);
  }
}

class _HostTile extends StatelessWidget {
  final Rec h;
  final bool? selected;
  final VoidCallback onTap;
  final void Function(Offset) onMenu;
  const _HostTile(this.h, {this.selected, required this.onTap, required this.onMenu});

  @override
  Widget build(BuildContext context) {
    final app = App.i;
    final scheme = Theme.of(context).colorScheme;
    final cred = app.store.get(h.get<String>('credential_id'));
    final state = app.sessions.hostState(h.id);
    final live = app.sessions.sessions.where((s) => s.hostId == h.id).toList();
    final connected = live.any((s) => s.state == SessionState.connected);
    final connecting = live.any((s) => s.state == SessionState.connecting);
    final order = h.str('auth_order', AuthOrder.keyThenPassword);
    final hasKey = cred?.get<String>('public_key') != null;
    final badge = cred == null
        ? 'NO LOGIN'
        : order == AuthOrder.keyOnly
            ? 'KEY'
            : order == AuthOrder.passwordOnly || !hasKey
                ? 'PASSWORD'
                : 'KEY → PW';
    final statusText = connected
        ? 'Connected'
        : connecting
            ? 'Connecting…'
            : state['status'] == 'failed'
                ? 'Last attempt failed · ${timeAgo(state['last_connected_at'] as int?)}'
                : 'Last used ${timeAgo(state['last_connected_at'] as int?)}';
    return GestureDetector(
      onSecondaryTapDown: (d) => onMenu(d.globalPosition),
      onLongPressStart: (d) => onMenu(d.globalPosition),
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: ConstrainedBox(
            constraints: const BoxConstraints(minHeight: 56),
            child: Row(children: [
              if (selected != null)
                Checkbox(value: selected, onChanged: (_) => onTap())
              else
                Container(
                  width: 10,
                  height: 10,
                  margin: const EdgeInsets.symmetric(horizontal: 9),
                  decoration: BoxDecoration(
                    color: connected ? scheme.primary : Colors.transparent,
                    border: Border.all(color: connected ? scheme.primary : C.host(h.get<String>('color')), width: 2),
                    shape: BoxShape.circle,
                  ),
                ),
              const SizedBox(width: 6),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
                  Row(children: [
                    Flexible(child: Text(h.str('nickname', h.str('hostname')), style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15), overflow: TextOverflow.ellipsis)),
                    if (h.flag('pinned')) Padding(padding: const EdgeInsets.only(left: 6), child: Icon(Icons.push_pin, size: 13, color: scheme.onSurfaceVariant)),
                    if (h.get<String>('jump_host_id') != null)
                      Padding(padding: const EdgeInsets.only(left: 6), child: Tooltip(message: 'Via jump host', child: Icon(Icons.alt_route, size: 14, color: scheme.onSurfaceVariant))),
                  ]),
                  const SizedBox(height: 2),
                  Text(hostAddress(h), style: TextStyle(fontFamily: mono, fontSize: 12, color: scheme.onSurfaceVariant), overflow: TextOverflow.ellipsis),
                  Text(statusText,
                      style: TextStyle(fontSize: 11, color: connected ? scheme.primary : scheme.onSurfaceVariant), overflow: TextOverflow.ellipsis),
                ]),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: cred == null ? scheme.tertiary : scheme.outline),
                ),
                child: Text(badge,
                    style: TextStyle(fontFamily: mono, fontSize: 10, fontWeight: FontWeight.w700, color: cred == null ? scheme.tertiary : scheme.onSurfaceVariant)),
              ),
              Builder(
                builder: (c) => IconButton(
                  tooltip: 'More',
                  icon: const Icon(Icons.more_vert, size: 20),
                  onPressed: () {
                    final box = c.findRenderObject() as RenderBox;
                    onMenu(box.localToGlobal(box.size.center(Offset.zero)));
                  },
                ),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}

class GroupsScreen extends StatelessWidget {
  const GroupsScreen({super.key});
  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: App.i,
        builder: (context, _) {
          final app = App.i;
          return Scaffold(
            appBar: AppBar(title: const Text('Groups')),
            floatingActionButton: FloatingActionButton.extended(
              icon: const Icon(Icons.add),
              label: const Text('New group'),
              onPressed: () async {
                final n = await askText(context, 'New group', label: 'Name');
                if (n != null && n.trim().isNotEmpty) app.store.put(RecordType.group, {'name': n.trim()});
              },
            ),
            body: ListView(children: [
              for (final g in app.groups)
                ListTile(
                  title: Text(g.str('name')),
                  subtitle: Text('${app.hosts.where((h) => h.get<String>('group_id') == g.id).length} hosts'),
                  trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                    IconButton(
                        tooltip: 'Rename',
                        icon: const Icon(Icons.edit_outlined),
                        onPressed: () async {
                          final n = await askText(context, 'Rename group', label: 'Name', initial: g.str('name'));
                          if (n != null && n.trim().isNotEmpty) app.store.update(g.id, {'name': n.trim()});
                        }),
                    IconButton(
                        tooltip: 'Delete',
                        icon: const Icon(Icons.delete_outline),
                        onPressed: () async {
                          if (await confirm(context, 'Delete group?', 'Hosts in it are kept and become ungrouped.', action: 'Delete', danger: true)) {
                            app.store.delete(g.id);
                          }
                        }),
                  ]),
                ),
              if (app.groups.isEmpty) const Padding(padding: EdgeInsets.all(24), child: Center(child: Text('No groups yet.'))),
            ]),
          );
        },
      );
}

/// Create or edit a host.
class HostEditor extends StatefulWidget {
  final Rec? host;
  const HostEditor({super.key, this.host});
  @override
  State<HostEditor> createState() => _HostEditorState();
}

class _HostEditorState extends State<HostEditor> {
  late final Map<String, dynamic> f = {
    'nickname': '',
    'hostname': '',
    'port': 22,
    'credential_id': null,
    'jump_host_id': null,
    'auth_order': AuthOrder.keyThenPassword,
    'group_id': null,
    'tags': <String>[],
    'color': null,
    'pinned': false,
    'notes': '',
    'keepalive': 0,
    'startup_command': '',
    'encoding': 'utf8',
    'forwards': <Map<String, dynamic>>[],
    'legacy_algorithms': false,
    'auto_reconnect': false,
    ...?widget.host?.fields,
  };
  late final nick = TextEditingController(text: f['nickname'] as String?);
  late final hostname = TextEditingController(text: f['hostname'] as String?);
  late final port = TextEditingController(text: '${f['port'] ?? 22}');
  late final tags = TextEditingController(text: ((f['tags'] as List?) ?? []).join(', '));
  late final notes = TextEditingController(text: f['notes'] as String?);
  late final keepalive = TextEditingController(text: (f['keepalive'] ?? 0) == 0 ? '' : '${f['keepalive']}');
  late final startup = TextEditingController(text: f['startup_command'] as String?);
  late List<Map<String, dynamic>> forwards = [for (final x in (f['forwards'] as List?) ?? []) Map<String, dynamic>.from(x as Map)];
  String? error;

  App get app => App.i;

  void _save() {
    final p = int.tryParse(port.text.trim());
    if (hostname.text.trim().isEmpty) return setState(() => error = 'Enter a hostname or IP address.');
    if (p == null || p < 1 || p > 65535) return setState(() => error = 'Port must be between 1 and 65535.');
    final data = {
      ...f,
      'nickname': nick.text.trim().isEmpty ? hostname.text.trim() : nick.text.trim(),
      'hostname': hostname.text.trim(),
      'port': p,
      'tags': tags.text.split(',').map((t) => t.trim()).where((t) => t.isNotEmpty).toList(),
      'notes': notes.text,
      'keepalive': int.tryParse(keepalive.text.trim()) ?? 0,
      'startup_command': startup.text,
      'forwards': forwards,
    };
    if (widget.host == null) {
      app.store.put(RecordType.host, data);
    } else {
      app.store.update(widget.host!.id, data);
    }
    Navigator.pop(context);
  }

  Future<void> _editForward([int? index]) async {
    final cur = index == null ? <String, dynamic>{'kind': 'L', 'bind_host': '127.0.0.1'} : Map<String, dynamic>.from(forwards[index]);
    final bp = TextEditingController(text: '${cur['bind_port'] ?? ''}');
    final bh = TextEditingController(text: '${cur['bind_host'] ?? '127.0.0.1'}');
    final dh = TextEditingController(text: '${cur['dest_host'] ?? ''}');
    final dp = TextEditingController(text: '${cur['dest_port'] ?? ''}');
    var kind = cur['kind'] as String;
    final r = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (c) => StatefulBuilder(
        builder: (c, set) => AlertDialog(
          title: const Text('Port forward'),
          content: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              SegmentedButton<String>(
                segments: const [
                  ButtonSegment(value: 'L', label: Text('Local')),
                  ButtonSegment(value: 'R', label: Text('Remote')),
                  ButtonSegment(value: 'D', label: Text('SOCKS')),
                ],
                selected: {kind},
                onSelectionChanged: (v) => set(() => kind = v.first),
              ),
              const SizedBox(height: 8),
              Text(
                  kind == 'L'
                      ? 'Listen on this device; connections go to the destination as seen from the server.'
                      : kind == 'R'
                          ? 'Listen on the server; connections come back to the destination as seen from this device.'
                          : 'A SOCKS5 proxy on this device that sends traffic through the server.',
                  style: Theme.of(c).textTheme.bodySmall),
              const SizedBox(height: 12),
              Row(children: [
                Expanded(flex: 3, child: TextField(controller: bh, decoration: const InputDecoration(labelText: 'Listen address'))),
                const SizedBox(width: 8),
                Expanded(flex: 2, child: TextField(controller: bp, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Port'))),
              ]),
              if (kind != 'D') ...[
                const SizedBox(height: 12),
                Row(children: [
                  Expanded(flex: 3, child: TextField(controller: dh, decoration: const InputDecoration(labelText: 'Destination host'))),
                  const SizedBox(width: 8),
                  Expanded(flex: 2, child: TextField(controller: dp, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Port'))),
                ]),
              ],
            ]),
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c), child: const Text('Cancel')),
            FilledButton(
              onPressed: () {
                final b = int.tryParse(bp.text.trim()), d = int.tryParse(dp.text.trim());
                if (b == null || b < 1 || b > 65535) return;
                if (kind != 'D' && (d == null || d < 1 || d > 65535 || dh.text.trim().isEmpty)) return;
                Navigator.pop(c, {
                  'kind': kind,
                  'bind_host': bh.text.trim().isEmpty ? '127.0.0.1' : bh.text.trim(),
                  'bind_port': b,
                  'dest_host': kind == 'D' ? '' : dh.text.trim(),
                  'dest_port': kind == 'D' ? 0 : d,
                });
              },
              child: const Text('Save'),
            ),
          ],
        ),
      ),
    );
    if (r == null) return;
    setState(() => index == null ? forwards.add(r) : forwards[index] = r);
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final creds = app.credentials;
    final cred = app.store.get(f['credential_id'] as String?);
    final others = app.hosts.where((h) => h.id != widget.host?.id).toList()
      ..sort((a, b) => a.str('nickname').compareTo(b.str('nickname')));
    Widget gap = const SizedBox(height: 14);
    Widget label(String s) => Padding(
        padding: const EdgeInsets.only(top: 22, bottom: 8),
        child: Text(s.toUpperCase(), style: Theme.of(context).textTheme.labelMedium?.copyWith(color: scheme.onSurfaceVariant, letterSpacing: 0.8)));

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.host == null ? 'New host' : 'Edit host'),
        actions: [Padding(padding: const EdgeInsets.only(right: 8), child: FilledButton(onPressed: _save, child: const Text('Save')))],
      ),
      body: ListView(padding: const EdgeInsets.fromLTRB(20, 4, 20, 40), children: [
        Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 560),
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              if (error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(error!, style: TextStyle(color: scheme.error))),
              label('Host'),
              TextField(controller: nick, decoration: const InputDecoration(labelText: 'Nickname')),
              gap,
              Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Expanded(
                    flex: 4,
                    child: TextField(
                        controller: hostname,
                        autocorrect: false,
                        keyboardType: TextInputType.url,
                        style: const TextStyle(fontFamily: mono),
                        decoration: const InputDecoration(labelText: 'Hostname or IP'))),
                const SizedBox(width: 10),
                Expanded(
                    flex: 2,
                    child: TextField(
                        controller: port,
                        keyboardType: TextInputType.number,
                        style: const TextStyle(fontFamily: mono),
                        decoration: const InputDecoration(labelText: 'Port'))),
              ]),
              label('Login'),
              DropdownButtonFormField<String?>(
                initialValue: cred?.id,
                isExpanded: true,
                decoration: const InputDecoration(labelText: 'Credential'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('None')),
                  for (final c in creds)
                    DropdownMenuItem(value: c.id, child: Text('${c.str('label')}  ·  ${c.str('username')}', overflow: TextOverflow.ellipsis)),
                ],
                onChanged: (v) => setState(() => f['credential_id'] = v),
              ),
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton.icon(
                  icon: const Icon(Icons.add, size: 18),
                  label: const Text('New credential'),
                  onPressed: () async {
                    final id = await Navigator.push<String>(context, MaterialPageRoute(builder: (_) => const CredentialEditor()));
                    if (id != null) setState(() => f['credential_id'] = id);
                  },
                ),
              ),
              const SizedBox(height: 4),
              Text('Login order', style: Theme.of(context).textTheme.bodySmall?.copyWith(color: scheme.onSurfaceVariant)),
              const SizedBox(height: 6),
              SegmentedButton<String>(
                showSelectedIcon: false,
                segments: const [
                  ButtonSegment(value: AuthOrder.keyThenPassword, label: Text('Key → password')),
                  ButtonSegment(value: AuthOrder.keyOnly, label: Text('Key only')),
                  ButtonSegment(value: AuthOrder.passwordOnly, label: Text('Password only')),
                ],
                selected: {f['auth_order'] as String? ?? AuthOrder.keyThenPassword},
                onSelectionChanged: (v) => setState(() => f['auth_order'] = v.first),
              ),
              if (f['auth_order'] == AuthOrder.keyOnly && cred != null && cred.get<String>('public_key') == null)
                Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text('This credential has no key, so "Key only" cannot log in.', style: TextStyle(color: scheme.tertiary))),
              label('Organise'),
              DropdownButtonFormField<String?>(
                initialValue: app.store.get(f['group_id'] as String?)?.id,
                isExpanded: true,
                decoration: const InputDecoration(labelText: 'Group'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('None')),
                  for (final g in app.groups) DropdownMenuItem(value: g.id, child: Text(g.str('name'))),
                  const DropdownMenuItem(value: '__new', child: Text('New group…')),
                ],
                onChanged: (v) async {
                  if (v == '__new') {
                    final n = await askText(context, 'New group', label: 'Name');
                    if (n == null || n.trim().isEmpty) return setState(() {});
                    v = app.store.put(RecordType.group, {'name': n.trim()});
                  }
                  setState(() => f['group_id'] = v);
                },
              ),
              gap,
              TextField(controller: tags, decoration: const InputDecoration(labelText: 'Tags', hintText: 'comma, separated')),
              gap,
              Row(children: [
                const Text('Colour'),
                const SizedBox(width: 12),
                for (final e in C.hostColors.entries)
                  Semantics(
                    label: e.key,
                    selected: f['color'] == e.key,
                    button: true,
                    child: InkWell(
                      customBorder: const CircleBorder(),
                      onTap: () => setState(() => f['color'] = f['color'] == e.key ? null : e.key),
                      child: Padding(
                        padding: const EdgeInsets.all(9),
                        child: Container(
                          width: 26,
                          height: 26,
                          decoration: BoxDecoration(
                              color: e.value,
                              shape: BoxShape.circle,
                              border: Border.all(color: f['color'] == e.key ? scheme.onSurface : Colors.transparent, width: 3)),
                        ),
                      ),
                    ),
                  ),
              ]),
              SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Pinned'),
                  value: f['pinned'] == true,
                  onChanged: (v) => setState(() => f['pinned'] = v)),
              TextField(controller: notes, maxLines: null, minLines: 2, decoration: const InputDecoration(labelText: 'Notes')),
              label('Connection'),
              DropdownButtonFormField<String?>(
                initialValue: app.store.get(f['jump_host_id'] as String?)?.id,
                isExpanded: true,
                decoration: const InputDecoration(labelText: 'Connect via (jump host)'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('Direct')),
                  for (final h in others) DropdownMenuItem(value: h.id, child: Text(h.str('nickname'), overflow: TextOverflow.ellipsis)),
                ],
                onChanged: (v) => setState(() => f['jump_host_id'] = v),
              ),
              gap,
              TextField(
                  controller: keepalive,
                  keyboardType: TextInputType.number,
                  decoration: InputDecoration(labelText: 'Keepalive interval (seconds)', hintText: 'Default (${app.setting<int>('keepalive')})')),
              gap,
              TextField(
                  controller: startup,
                  autocorrect: false,
                  style: const TextStyle(fontFamily: mono, fontSize: 14),
                  decoration: const InputDecoration(labelText: 'Startup command', hintText: 'e.g. tmux attach || tmux')),
              gap,
              DropdownButtonFormField<String>(
                initialValue: f['encoding'] == 'latin1' ? 'latin1' : 'utf8',
                decoration: const InputDecoration(labelText: 'Terminal encoding'),
                items: const [
                  DropdownMenuItem(value: 'utf8', child: Text('UTF-8')),
                  DropdownMenuItem(value: 'latin1', child: Text('Latin-1 (ISO 8859-1)')),
                ],
                onChanged: (v) => setState(() => f['encoding'] = v),
              ),
              SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Reconnect automatically'),
                  subtitle: const Text('Retries with increasing delays if the connection drops'),
                  value: f['auto_reconnect'] == true,
                  onChanged: (v) => setState(() => f['auto_reconnect'] = v)),
              SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Allow legacy algorithms'),
                  subtitle: const Text('For old devices only: ssh-rsa host keys, CBC ciphers, SHA-1 key exchange'),
                  value: f['legacy_algorithms'] == true,
                  onChanged: (v) => setState(() => f['legacy_algorithms'] = v)),
              label('Port forwards'),
              for (var i = 0; i < forwards.length; i++)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.swap_horiz),
                  title: Text(ForwardSpec.fromJson(forwards[i]).label, style: const TextStyle(fontFamily: mono, fontSize: 13)),
                  onTap: () => _editForward(i),
                  trailing: IconButton(tooltip: 'Remove', icon: const Icon(Icons.close), onPressed: () => setState(() => forwards.removeAt(i))),
                ),
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton.icon(icon: const Icon(Icons.add, size: 18), label: const Text('Add forward'), onPressed: _editForward),
              ),
            ]),
          ),
        ),
      ]),
    );
  }
}
