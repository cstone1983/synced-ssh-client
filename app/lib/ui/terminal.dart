import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:sshsync_core/sshsync_core.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:xterm/xterm.dart';

import '../services.dart';
import '../theme.dart';
import 'dialogs.dart';

/// The terminal emulator state for one session. Lives outside the widget
/// tree so scrollback survives switching screens and locking.
class Term {
  final TerminalSession session;
  final Terminal terminal;
  final controller = TerminalController();
  final focus = FocusNode();

  /// Sticky modifiers from the extra-keys row; apply to the next key.
  final ctrl = ValueNotifier(false), alt = ValueNotifier(false);

  Term(this.session, int scrollback) : terminal = Terminal(maxLines: scrollback) {
    session.onData = terminal.write;
    terminal.onResize = (w, h, _, _) => session.resize(w, h);
    terminal.onOutput = (data) {
      var out = data;
      if (ctrl.value && data.length == 1) {
        final c = data.toUpperCase().codeUnitAt(0);
        if (c >= 0x40 && c <= 0x5f) out = String.fromCharCode(c & 0x1f);
        if (data == ' ') out = '\x00';
      }
      if (alt.value) out = '\x1b$out';
      ctrl.value = alt.value = false;
      session.write(out);
    };
  }

  void key(TerminalKey k) {
    terminal.keyInput(k, ctrl: ctrl.value, alt: alt.value);
    ctrl.value = alt.value = false;
  }

  String? get selectedText {
    final sel = controller.selection;
    return sel == null ? null : terminal.buffer.getText(sel);
  }

  Future<void> copy(BuildContext context) async {
    final text = selectedText;
    if (text == null || text.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: text));
    controller.clearSelection();
    if (context.mounted) toast(context, 'Copied');
  }

  Future<void> paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text;
    if (text != null && text.isNotEmpty) terminal.paste(text);
  }
}

class Terms {
  static final _all = <String, Term>{};

  static Term of(TerminalSession s) =>
      _all[s.id] ??= Term(s, App.i.setting<int>('scrollback'));

  static void prune(List<TerminalSession> live) {
    final ids = {for (final s in live) s.id};
    _all.removeWhere((id, _) => !ids.contains(id));
  }
}

final _urlPattern = RegExp(r'''https?://[^\s<>"'`\])}]+''');

/// One terminal with its status banner and (on touch devices) extra keys.
class TerminalPane extends StatefulWidget {
  final TerminalSession session;
  final bool autofocus;

  /// Desktop shortcuts that belong to the tab bar (new/close/next/previous).
  final KeyEventResult Function(KeyEvent event)? onShortcut;
  const TerminalPane(this.session, {super.key, this.autofocus = true, this.onShortcut});
  @override
  State<TerminalPane> createState() => _TerminalPaneState();
}

class _TerminalPaneState extends State<TerminalPane> {
  final _pointers = <int, Offset>{};
  double? _pinchStart, _pinchFont;

  Term get term => Terms.of(widget.session);
  double get _font => App.i.setting<double>('font_size');
  void _setFont(double v) => App.i.setSetting('font_size', v.clamp(8.0, 32.0));

  bool get _touch => Platform.isAndroid;

  KeyEventResult _onKey(FocusNode node, KeyEvent e) {
    if (e is KeyUpEvent) return KeyEventResult.ignored;
    final hk = HardwareKeyboard.instance;
    final k = e.logicalKey;
    if (hk.isControlPressed && hk.isShiftPressed) {
      if (k == LogicalKeyboardKey.keyC) {
        term.copy(context);
        return KeyEventResult.handled;
      }
      if (k == LogicalKeyboardKey.keyV) {
        term.paste();
        return KeyEventResult.handled;
      }
    }
    if (hk.isControlPressed) {
      if (k == LogicalKeyboardKey.equal || k == LogicalKeyboardKey.add) {
        _setFont(_font + 1);
        return KeyEventResult.handled;
      }
      if (k == LogicalKeyboardKey.minus) {
        _setFont(_font - 1);
        return KeyEventResult.handled;
      }
    }
    if (App.i.setting<bool>('volume_zoom')) {
      if (k == LogicalKeyboardKey.audioVolumeUp) {
        _setFont(_font + 1);
        return KeyEventResult.handled;
      }
      if (k == LogicalKeyboardKey.audioVolumeDown) {
        _setFont(_font - 1);
        return KeyEventResult.handled;
      }
    }
    final shortcut = widget.onShortcut?.call(e) ?? KeyEventResult.ignored;
    if (shortcut != KeyEventResult.ignored) return shortcut;
    // Desktop: type printable characters straight from key events. The
    // widget's text-input path can duplicate characters when typing fast.
    // Ctrl combinations and Alt+key fall through to the terminal's own
    // handling; Ctrl+Alt together is AltGr on many layouts, so it types.
    if (!_touch) {
      final ch = e.character;
      final ctrl = hk.isControlPressed, alt = hk.isAltPressed;
      if (ch != null && ch.isNotEmpty && ctrl == alt) {
        final c = ch.codeUnitAt(0);
        if (c >= 0x20 && c != 0x7f) {
          term.terminal.textInput(ch);
          return KeyEventResult.handled;
        }
      }
    }
    return KeyEventResult.ignored;
  }

  void _tap(TapUpDetails d, CellOffset cell) {
    final buffer = term.terminal.buffer;
    if (cell.y < 0 || cell.y >= buffer.height) return;
    final line = buffer.lines[cell.y].getText();
    for (final m in _urlPattern.allMatches(line)) {
      if (cell.x >= m.start && cell.x < m.end) {
        final url = m.group(0)!.replaceAll(RegExp(r'[.,;:]+$'), '');
        ScaffoldMessenger.of(context)
          ..hideCurrentSnackBar()
          ..showSnackBar(SnackBar(
            content: Text(url, maxLines: 2, overflow: TextOverflow.ellipsis),
            action: SnackBarAction(
                label: 'Open',
                onPressed: () => launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication)),
          ));
        return;
      }
    }
  }

  void _pinch() {
    if (_pointers.length != 2) {
      _pinchStart = null;
      return;
    }
    final p = _pointers.values.toList();
    final dist = (p[0] - p[1]).distance;
    if (_pinchStart == null) {
      _pinchStart = dist;
      _pinchFont = _font;
    } else if (dist > 0 && _pinchStart! > 0) {
      final next = (_pinchFont! * dist / _pinchStart!).roundToDouble();
      if (next != _font) _setFont(next);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = widget.session;
    final theme = (terminalThemes[App.i.setting<String>('term_theme')] ?? terminalThemes['default']!).$2;
    return Column(children: [
      if (s.state != SessionState.connected) _StatusBanner(s),
      if (s.forwards.isNotEmpty) _Forwards(s),
      Expanded(
        child: Listener(
          onPointerDown: (e) {
            _pointers[e.pointer] = e.position;
            _pinch();
          },
          onPointerMove: (e) {
            if (_pointers.containsKey(e.pointer)) {
              _pointers[e.pointer] = e.position;
              if (_pointers.length == 2) _pinch();
            }
          },
          onPointerUp: (e) {
            _pointers.remove(e.pointer);
            _pinchStart = null;
          },
          onPointerCancel: (e) {
            _pointers.remove(e.pointer);
            _pinchStart = null;
          },
          onPointerSignal: (e) {
            if (e is PointerScrollEvent && HardwareKeyboard.instance.isControlPressed) {
              _setFont(_font + (e.scrollDelta.dy < 0 ? 1 : -1));
            }
          },
          child: ColoredBox(
            color: theme.background,
            child: TerminalView(
              term.terminal,
              controller: term.controller,
              focusNode: term.focus,
              autofocus: widget.autofocus,
              theme: theme,
              textStyle: TerminalStyle(fontFamily: mono, fontSize: _font),
              padding: const EdgeInsets.all(6),
              keyboardType: TextInputType.visiblePassword,
              deleteDetection: _touch,
              hardwareKeyboardOnly: !_touch,
              onKeyEvent: _onKey,
              onTapUp: _tap,
              onSecondaryTapDown: (d, _) => _contextMenu(d.globalPosition),
            ),
          ),
        ),
      ),
      if (_touch) ExtraKeys(term),
    ]);
  }

  Future<void> _contextMenu(Offset at) async {
    final v = await showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(at.dx, at.dy, at.dx, at.dy),
      items: [
        PopupMenuItem(value: 'copy', enabled: term.selectedText?.isNotEmpty ?? false, child: const Text('Copy')),
        const PopupMenuItem(value: 'paste', child: Text('Paste')),
      ],
    );
    if (!mounted) return;
    if (v == 'copy') await term.copy(context);
    if (v == 'paste') await term.paste();
  }
}

class _StatusBanner extends StatelessWidget {
  final TerminalSession s;
  const _StatusBanner(this.s);
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final connecting = s.state == SessionState.connecting;
    final color = connecting ? scheme.secondary : scheme.tertiary;
    return Material(
      color: color.withValues(alpha: 0.14),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Row(children: [
          if (connecting)
            const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
          else
            Icon(Icons.link_off, size: 18, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              connecting
                  ? 'Connecting to ${s.spec.host}…'
                  : '${s.error ?? 'Disconnected.'}'
                      '${s.reconnectIn != null ? ' Retrying in ${s.reconnectIn}s.' : ''}',
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (!connecting) ...[
            if (s.reconnectIn != null) TextButton(onPressed: s.cancelReconnect, child: const Text('Stop')),
            FilledButton.tonal(onPressed: s.connect, child: const Text('Reconnect')),
          ],
        ]),
      ),
    );
  }
}

class _Forwards extends StatelessWidget {
  final TerminalSession s;
  const _Forwards(this.s);
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      width: double.infinity,
      color: scheme.surface,
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      child: Wrap(spacing: 12, runSpacing: 2, children: [
        for (final f in s.forwards)
          Tooltip(
            message: f.error ?? (f.active ? '${f.connections} open connection(s)' : 'Stopped'),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              Icon(f.active ? Icons.swap_horiz : Icons.error_outline,
                  size: 15, color: f.active ? scheme.primary : scheme.error),
              const SizedBox(width: 4),
              Text('${f.spec.label}${f.error != null ? ' — ${f.error}' : ''}',
                  style: TextStyle(fontFamily: mono, fontSize: 11, color: f.active ? scheme.onSurfaceVariant : scheme.error)),
            ]),
          ),
      ]),
    );
  }
}

/// Keys a phone keyboard lacks. Ctrl and Alt are sticky: tap, then type.
class ExtraKeys extends StatelessWidget {
  final Term term;
  const ExtraKeys(this.term, {super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    Widget cap(String label, VoidCallback onTap, {bool active = false, String? semantics, IconData? icon}) => Semantics(
          button: true,
          label: semantics ?? label,
          toggled: active ? true : null,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 2),
            child: Material(
              color: active ? scheme.primary : scheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(8),
              child: InkWell(
                borderRadius: BorderRadius.circular(8),
                onTap: () {
                  HapticFeedback.selectionClick();
                  onTap();
                },
                child: ConstrainedBox(
                  constraints: const BoxConstraints(minWidth: 46, minHeight: 44),
                  child: Center(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 8),
                      child: icon != null
                          ? Icon(icon, size: 18, color: scheme.onSurface)
                          : Text(label,
                              style: TextStyle(
                                  fontFamily: mono,
                                  fontSize: 13,
                                  fontWeight: FontWeight.w600,
                                  color: active ? scheme.onPrimary : scheme.onSurface)),
                    ),
                  ),
                ),
              ),
            ),
          ),
        );
    Widget key(String label, TerminalKey k, {IconData? icon, String? semantics}) =>
        cap(label, () => term.key(k), icon: icon, semantics: semantics);
    Widget ch(String c) => cap(c, () => term.terminal.textInput(c));

    return Material(
      color: scheme.surface,
      child: SafeArea(
        top: false,
        child: SizedBox(
          height: 52,
          child: ListenableBuilder(
            listenable: Listenable.merge([term.ctrl, term.alt]),
            builder: (context, _) => ListView(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
              children: [
                key('Esc', TerminalKey.escape),
                cap('Ctrl', () => term.ctrl.value = !term.ctrl.value, active: term.ctrl.value),
                cap('Alt', () => term.alt.value = !term.alt.value, active: term.alt.value),
                key('Tab', TerminalKey.tab),
                ch('/'),
                ch('|'),
                ch('~'),
                ch('-'),
                key('←', TerminalKey.arrowLeft, icon: Icons.arrow_back, semantics: 'Left'),
                key('↑', TerminalKey.arrowUp, icon: Icons.arrow_upward, semantics: 'Up'),
                key('↓', TerminalKey.arrowDown, icon: Icons.arrow_downward, semantics: 'Down'),
                key('→', TerminalKey.arrowRight, icon: Icons.arrow_forward, semantics: 'Right'),
                key('Home', TerminalKey.home),
                key('End', TerminalKey.end),
                key('PgUp', TerminalKey.pageUp),
                key('PgDn', TerminalKey.pageDown),
                cap('Paste', term.paste, icon: Icons.content_paste, semantics: 'Paste'),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Tabs of open sessions, optionally two side by side on wide screens.
class SessionsView extends StatefulWidget {
  final bool wide;
  final VoidCallback? onNewTab;
  const SessionsView({super.key, required this.wide, this.onNewTab});
  @override
  State<SessionsView> createState() => SessionsViewState();
}

/// Which session is in front; shared so "connect" can bring a tab forward.
final currentSession = ValueNotifier<String?>(null);

class SessionsViewState extends State<SessionsView> {
  bool split = false;
  String? secondId;

  List<TerminalSession> get all => App.i.sessions.sessions;

  TerminalSession? get current {
    if (all.isEmpty) return null;
    return all.firstWhere((s) => s.id == currentSession.value, orElse: () => all.last);
  }

  void _step(int by) {
    final cur = current;
    if (cur == null) return;
    final i = (all.indexOf(cur) + by) % all.length;
    currentSession.value = all[i < 0 ? i + all.length : i].id;
  }

  void _close(TerminalSession s) async {
    if (s.state == SessionState.connected &&
        !await confirm(context, 'Close session?', 'This disconnects from ${s.title}.', action: 'Disconnect')) {
      return;
    }
    App.i.sessions.close(s);
  }

  KeyEventResult _shortcut(KeyEvent e) {
    final hk = HardwareKeyboard.instance;
    if (!hk.isControlPressed) return KeyEventResult.ignored;
    final k = e.logicalKey;
    if (k == LogicalKeyboardKey.tab) {
      _step(hk.isShiftPressed ? -1 : 1);
      return KeyEventResult.handled;
    }
    if (hk.isShiftPressed && k == LogicalKeyboardKey.keyW) {
      final c = current;
      if (c != null) _close(c);
      return KeyEventResult.handled;
    }
    if (hk.isShiftPressed && k == LogicalKeyboardKey.keyT) {
      widget.onNewTab?.call();
      return KeyEventResult.handled;
    }
    return KeyEventResult.ignored;
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return ListenableBuilder(
      listenable: Listenable.merge([App.i, currentSession]),
      builder: (context, _) {
        Terms.prune(all);
        final cur = current;
        if (cur == null) {
          return Center(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Icon(Icons.terminal, size: 48, color: scheme.onSurfaceVariant),
              const SizedBox(height: 12),
              const Text('No open sessions'),
              const SizedBox(height: 4),
              Text(widget.wide ? 'Pick a host on the left, or type user@host above it.' : 'Pick a host on the Hosts tab.',
                  style: TextStyle(color: scheme.onSurfaceVariant)),
            ]),
          );
        }
        final others = all.where((s) => s.id != cur.id).toList();
        final second = split && widget.wide && others.isNotEmpty
            ? others.firstWhere((s) => s.id == secondId, orElse: () => others.first)
            : null;
        return Column(children: [
          Material(
            color: scheme.surface,
            child: SizedBox(
              height: 46,
              child: Row(children: [
                Expanded(
                  child: ListView(
                    scrollDirection: Axis.horizontal,
                    children: [for (final s in all) _Tab(s, s.id == cur.id, () => currentSession.value = s.id, () => _close(s))],
                  ),
                ),
                if (widget.wide && all.length > 1)
                  IconButton(
                    tooltip: split ? 'Single view' : 'Split view',
                    isSelected: split,
                    icon: const Icon(Icons.vertical_split_outlined),
                    selectedIcon: const Icon(Icons.vertical_split),
                    onPressed: () => setState(() => split = !split),
                  ),
                IconButton(tooltip: 'Copy selection', icon: const Icon(Icons.copy), onPressed: () => Terms.of(cur).copy(context)),
                IconButton(tooltip: 'Paste', icon: const Icon(Icons.content_paste), onPressed: () => Terms.of(cur).paste()),
              ]),
            ),
          ),
          Expanded(
            child: second == null
                ? TerminalPane(cur, key: ValueKey(cur.id), onShortcut: _shortcut)
                : Row(children: [
                    Expanded(child: TerminalPane(cur, key: ValueKey(cur.id), onShortcut: _shortcut)),
                    VerticalDivider(width: 1, color: scheme.outlineVariant),
                    Expanded(
                      child: Column(children: [
                        Material(
                          color: scheme.surface,
                          child: Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 10),
                            child: DropdownButton<String>(
                              isExpanded: true,
                              underline: const SizedBox(),
                              value: second.id,
                              items: [for (final s in others) DropdownMenuItem(value: s.id, child: Text(s.title))],
                              onChanged: (v) => setState(() => secondId = v),
                            ),
                          ),
                        ),
                        Expanded(child: TerminalPane(second, key: ValueKey('second-${second.id}'), autofocus: false, onShortcut: _shortcut)),
                      ]),
                    ),
                  ]),
          ),
        ]);
      },
    );
  }
}

class _Tab extends StatelessWidget {
  final TerminalSession s;
  final bool selected;
  final VoidCallback onTap, onClose;
  const _Tab(this.s, this.selected, this.onTap, this.onClose);
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final dot = switch (s.state) {
      SessionState.connected => scheme.primary,
      SessionState.connecting => scheme.secondary,
      SessionState.disconnected => scheme.tertiary,
    };
    return Semantics(
      selected: selected,
      button: true,
      label: '${s.title}, ${s.state.name}',
      child: InkWell(
        onTap: onTap,
        child: Container(
          constraints: BoxConstraints(minWidth: 120, maxWidth: math.max(120, 220)),
          padding: const EdgeInsets.only(left: 12),
          decoration: BoxDecoration(
            color: selected ? Theme.of(context).scaffoldBackgroundColor : null,
            border: Border(bottom: BorderSide(color: selected ? scheme.primary : Colors.transparent, width: 2)),
          ),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Container(width: 8, height: 8, decoration: BoxDecoration(color: dot, shape: BoxShape.circle)),
            const SizedBox(width: 8),
            Flexible(child: Text(s.title, overflow: TextOverflow.ellipsis, style: TextStyle(fontWeight: selected ? FontWeight.w600 : FontWeight.w400))),
            IconButton(
                tooltip: 'Close ${s.title}',
                icon: const Icon(Icons.close, size: 16),
                constraints: const BoxConstraints(minWidth: 44, minHeight: 44),
                onPressed: onClose),
          ]),
        ),
      ),
    );
  }
}
