import 'dart:io';

import 'package:flutter/material.dart';
import 'package:sshsync_core/sshsync_core.dart';

import '../services.dart';
import 'hosts.dart';
import 'settings.dart';
import 'sync.dart';
import 'terminal.dart';
import 'vault.dart';

/// Adaptive frame: bottom navigation on phones, sidebar + tabs on wide
/// windows.
class AppShell extends StatefulWidget {
  const AppShell({super.key});
  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  int index = 0; // narrow: Hosts, Sessions, Vault, Sync. wide: 0 terminals, 2 vault, 3 sync, 4 settings
  final quickFocus = FocusNode();

  App get app => App.i;

  @override
  void initState() {
    super.initState();
    final n = app.interruptedSessions;
    if (n > 0) {
      app.interruptedSessions = 0;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          duration: const Duration(seconds: 10),
          content: Text(Platform.isAndroid
              ? 'Android stopped the app while $n SSH session${n == 1 ? ' was' : 's were'} open. '
                  'Allowing unrestricted battery use in Settings makes this less likely.'
              : 'The app closed while $n SSH session${n == 1 ? ' was' : 's were'} open.'),
        ));
      });
    }
  }

  void _newHost() => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const HostEditor()));

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: app,
        builder: (context, _) => LayoutBuilder(builder: (context, box) => box.maxWidth >= 900 ? _wide(context) : _narrow(context)),
      );

  Widget _badge(Widget icon, int n) => n == 0 ? icon : Badge(label: Text('$n'), child: icon);

  Widget _narrow(BuildContext context) {
    final i = index.clamp(0, 3);
    final active = app.sessions.sessions.length;
    final attention = app.conflicts.length;
    return Scaffold(
      appBar: i == 0
          ? AppBar(title: const Text('Hosts'), actions: [
              IconButton(tooltip: 'Lock now', icon: const Icon(Icons.lock_outline), onPressed: app.lock),
              IconButton(
                  tooltip: 'Settings',
                  icon: const Icon(Icons.settings_outlined),
                  onPressed: () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const SettingsScreen()))),
            ])
          : null,
      floatingActionButton: i == 0 ? FloatingActionButton(tooltip: 'New host', onPressed: _newHost, child: const Icon(Icons.add)) : null,
      body: SafeArea(
        top: i == 1,
        bottom: false,
        child: IndexedStack(index: i, children: [
          HostsPane(onConnected: () => setState(() => index = 1)),
          const SessionsView(wide: false),
          const VaultScreen(),
          const SyncScreen(),
        ]),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: i,
        onDestinationSelected: (v) => setState(() => index = v),
        destinations: [
          const NavigationDestination(icon: Icon(Icons.dns_outlined), selectedIcon: Icon(Icons.dns), label: 'Hosts'),
          NavigationDestination(icon: _badge(const Icon(Icons.terminal), active), label: 'Sessions'),
          const NavigationDestination(icon: Icon(Icons.key_outlined), selectedIcon: Icon(Icons.key), label: 'Vault'),
          NavigationDestination(icon: _badge(const Icon(Icons.sync), attention), label: 'Sync'),
        ],
      ),
    );
  }

  Widget _wide(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final i = (index == 1) ? 0 : index;
    final phase = app.sync.status?.phase;
    Widget rail(int target, IconData icon, String tip, {int badge = 0, VoidCallback? onTap}) => Tooltip(
          message: tip,
          child: InkWell(
            onTap: onTap ?? () => setState(() => index = target),
            child: Container(
              width: 56,
              height: 52,
              decoration: BoxDecoration(border: Border(left: BorderSide(color: onTap == null && i == target ? scheme.primary : Colors.transparent, width: 3))),
              child: Center(child: _badge(Icon(icon, color: onTap == null && i == target ? scheme.primary : scheme.onSurfaceVariant), badge)),
            ),
          ),
        );
    return Scaffold(
      body: SafeArea(
        child: Row(children: [
          Material(
            color: scheme.surface,
            child: Column(children: [
              const SizedBox(height: 8),
              rail(0, Icons.terminal, 'Terminals', badge: app.sessions.sessions.length),
              rail(2, Icons.key_outlined, 'Vault'),
              rail(3, phase == SyncPhase.offline || phase == SyncPhase.error ? Icons.sync_problem : Icons.sync, 'Sync', badge: app.conflicts.length),
              const Spacer(),
              rail(4, Icons.settings_outlined, 'Settings'),
              rail(-1, Icons.lock_outline, 'Lock now', onTap: app.lock),
              const SizedBox(height: 8),
            ]),
          ),
          VerticalDivider(width: 1, color: scheme.outlineVariant),
          SizedBox(
            width: 340,
            child: Column(children: [
              Expanded(child: HostsPane(quickFocus: quickFocus, onConnected: () => setState(() => index = 0))),
              Padding(
                padding: const EdgeInsets.all(12),
                child: SizedBox(width: double.infinity, child: OutlinedButton.icon(onPressed: _newHost, icon: const Icon(Icons.add), label: const Text('New host'))),
              ),
            ]),
          ),
          VerticalDivider(width: 1, color: scheme.outlineVariant),
          Expanded(
            child: IndexedStack(index: switch (i) { 2 => 1, 3 => 2, 4 => 3, _ => 0 }, children: [
              SessionsView(wide: true, onNewTab: quickFocus.requestFocus),
              const VaultScreen(),
              const SyncScreen(),
              const SettingsScreen(),
            ]),
          ),
        ]),
      ),
    );
  }
}
