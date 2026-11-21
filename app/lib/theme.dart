import 'package:flutter/material.dart';
import 'package:xterm/xterm.dart';

class C {
  static const ground = Color(0xFF0E1116);
  static const surface = Color(0xFF161B22);
  static const surfaceHigh = Color(0xFF1F2630);
  static const border = Color(0xFF2B3340);
  static const accent = Color(0xFF3DDC97);
  static const warning = Color(0xFFF0A04B);
  static const info = Color(0xFF5AB0FF);
  static const danger = Color(0xFFFF6B6B);
  static const text = Color(0xFFE6EDF3);
  static const muted = Color(0xFF9AA7B4);

  static const hostColors = <String, Color>{
    'green': accent,
    'blue': info,
    'orange': warning,
    'red': danger,
    'purple': Color(0xFFB392F0),
    'gray': muted,
  };
  static Color host(String? name) => hostColors[name] ?? muted;
}

const mono = 'JetBrainsMono';

ThemeData appTheme(bool dark) {
  final scheme = dark
      ? const ColorScheme.dark(
          primary: C.accent,
          onPrimary: Color(0xFF06281A),
          secondary: C.info,
          onSecondary: Color(0xFF04213A),
          surface: C.surface,
          onSurface: C.text,
          onSurfaceVariant: C.muted,
          surfaceContainerHighest: C.surfaceHigh,
          surfaceContainerHigh: C.surfaceHigh,
          surfaceContainer: C.surface,
          surfaceContainerLow: C.surface,
          outline: C.border,
          outlineVariant: C.border,
          error: C.danger,
          onError: Color(0xFF3A0A0A),
          tertiary: C.warning,
        )
      : const ColorScheme.light(
          primary: Color(0xFF0B7A50),
          onPrimary: Colors.white,
          secondary: Color(0xFF1668B8),
          surface: Colors.white,
          onSurface: Color(0xFF14181D),
          onSurfaceVariant: Color(0xFF4F5B67),
          surfaceContainerHighest: Color(0xFFE9EDF1),
          surfaceContainerHigh: Color(0xFFEFF2F5),
          surfaceContainer: Color(0xFFF4F6F8),
          surfaceContainerLow: Color(0xFFF7F9FA),
          outline: Color(0xFFC3CBD3),
          outlineVariant: Color(0xFFD9DFE5),
          error: Color(0xFFB3261E),
          tertiary: Color(0xFF9A5B00),
        );
  final base = ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    fontFamily: 'Inter',
    scaffoldBackgroundColor: dark ? C.ground : const Color(0xFFF4F6F8),
    visualDensity: VisualDensity.standard,
    materialTapTargetSize: MaterialTapTargetSize.padded,
  );
  return base.copyWith(
    appBarTheme: AppBarTheme(
      backgroundColor: dark ? C.ground : const Color(0xFFF4F6F8),
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      scrolledUnderElevation: 0,
      titleTextStyle: base.textTheme.titleLarge
          ?.copyWith(fontWeight: FontWeight.w600, fontSize: 20),
    ),
    cardTheme: CardThemeData(
      color: scheme.surface,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: scheme.outlineVariant)),
    ),
    dividerTheme: DividerThemeData(color: scheme.outlineVariant, space: 1),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: dark ? C.ground : Colors.white,
      border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: scheme.outline)),
      enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(color: scheme.outline)),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
    ),
    filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
            minimumSize: const Size(64, 48),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)))),
    outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
            minimumSize: const Size(64, 48),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)))),
    textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(minimumSize: const Size(48, 44))),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: scheme.surface,
      indicatorColor: scheme.primary.withValues(alpha: 0.18),
      surfaceTintColor: Colors.transparent,
    ),
    dialogTheme: DialogThemeData(
        backgroundColor: scheme.surface, surfaceTintColor: Colors.transparent),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      width: 520,
      backgroundColor: dark ? C.surfaceHigh : const Color(0xFF24292F),
      contentTextStyle: const TextStyle(color: Colors.white, fontFamily: 'Inter'),
      actionTextColor: C.accent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    ),
  );
}

TerminalTheme _t(int bg, int fg, int cursor, int sel, List<int> c) => TerminalTheme(
      cursor: Color(cursor),
      selection: Color(sel),
      foreground: Color(fg),
      background: Color(bg),
      black: Color(c[0]),
      red: Color(c[1]),
      green: Color(c[2]),
      yellow: Color(c[3]),
      blue: Color(c[4]),
      magenta: Color(c[5]),
      cyan: Color(c[6]),
      white: Color(c[7]),
      brightBlack: Color(c[8]),
      brightRed: Color(c[9]),
      brightGreen: Color(c[10]),
      brightYellow: Color(c[11]),
      brightBlue: Color(c[12]),
      brightMagenta: Color(c[13]),
      brightCyan: Color(c[14]),
      brightWhite: Color(c[15]),
      searchHitBackground: const Color(0xFFF0A04B),
      searchHitBackgroundCurrent: const Color(0xFF3DDC97),
      searchHitForeground: const Color(0xFF0E1116),
    );

final terminalThemes = <String, (String, TerminalTheme)>{
  'default': (
    'Midnight (default)',
    _t(0xFF0E1116, 0xFFE6EDF3, 0xFF3DDC97, 0x553DDC97, [
      0xFF1F2630, 0xFFFF6B6B, 0xFF3DDC97, 0xFFF0A04B, 0xFF5AB0FF, 0xFFB392F0, 0xFF56D4DD, 0xFFC9D1D9,
      0xFF6E7B8A, 0xFFFF8E8E, 0xFF6CE9B4, 0xFFF5BE7A, 0xFF85C5FF, 0xFFCBB2F7, 0xFF86E3EA, 0xFFFFFFFF,
    ])
  ),
  'solarized': (
    'Solarized Dark',
    _t(0xFF002B36, 0xFF93A1A1, 0xFF93A1A1, 0x55586E75, [
      0xFF073642, 0xFFDC322F, 0xFF859900, 0xFFB58900, 0xFF268BD2, 0xFFD33682, 0xFF2AA198, 0xFFEEE8D5,
      0xFF586E75, 0xFFCB4B16, 0xFF98AD00, 0xFFC9A000, 0xFF4BA3E0, 0xFF6C71C4, 0xFF35B8AE, 0xFFFDF6E3,
    ])
  ),
  'gruvbox': (
    'Gruvbox Dark',
    _t(0xFF282828, 0xFFEBDBB2, 0xFFEBDBB2, 0x55928374, [
      0xFF282828, 0xFFCC241D, 0xFF98971A, 0xFFD79921, 0xFF458588, 0xFFB16286, 0xFF689D6A, 0xFFA89984,
      0xFF928374, 0xFFFB4934, 0xFFB8BB26, 0xFFFABD2F, 0xFF83A598, 0xFFD3869B, 0xFF8EC07C, 0xFFEBDBB2,
    ])
  ),
  'light': (
    'Paper (light)',
    _t(0xFFFAFAFA, 0xFF24292F, 0xFF0B7A50, 0x440B7A50, [
      0xFF24292F, 0xFFCF222E, 0xFF116329, 0xFF7D4E00, 0xFF0969DA, 0xFF8250DF, 0xFF1B7C83, 0xFF6E7781,
      0xFF57606A, 0xFFA40E26, 0xFF1A7F37, 0xFF633C01, 0xFF218BFF, 0xFFA475F9, 0xFF3192AA, 0xFF8C959F,
    ])
  ),
};
