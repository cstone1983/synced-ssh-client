import 'dart:convert';

/// A host found by one of the importers, before it is stored.
class ImportedHost {
  String nickname;
  String hostname;
  int port;
  String? user;

  /// Path to the private key, exactly as written in the source.
  String? identityFile;

  /// Alias or host name of the first jump host (no user, no port).
  String? proxyJump;
  String? group;
  List<String> tags;

  ImportedHost({
    required this.nickname,
    required this.hostname,
    this.port = 22,
    this.user,
    this.identityFile,
    this.proxyJump,
    this.group,
    List<String>? tags,
  }) : tags = tags ?? [];

  @override
  String toString() => 'ImportedHost($nickname -> '
      '${user == null ? '' : '$user@'}$hostname:$port)';
}

class _Block {
  /// Null for the implicit global section before the first `Host`.
  final List<String>? patterns;
  final Map<String, String> options = {};
  String? group;
  List<String>? tags;
  _Block(this.patterns);

  bool matches(String alias) {
    final pats = patterns;
    if (pats == null) return true;
    var positive = false;
    for (final p in pats) {
      if (p.startsWith('!')) {
        if (_glob(p.substring(1), alias)) return false;
      } else if (_glob(p, alias)) {
        positive = true;
      }
    }
    return positive;
  }

  bool lists(String alias) => patterns?.contains(alias) ?? false;
}

bool _isPattern(String s) =>
    s.contains('*') || s.contains('?') || s.startsWith('!');

bool _glob(String pattern, String text) {
  final re = StringBuffer('^');
  for (final ch in pattern.split('')) {
    if (ch == '*') {
      re.write('.*');
    } else if (ch == '?') {
      re.write('.');
    } else {
      re.write(RegExp.escape(ch));
    }
  }
  re.write(r'$');
  return RegExp(re.toString()).hasMatch(text);
}

/// Splits an ssh_config argument string into tokens, honouring double quotes
/// and stopping at an unquoted `#` that starts a token.
List<String> _tokens(String s) {
  final out = <String>[];
  var i = 0;
  while (i < s.length) {
    while (i < s.length && (s[i] == ' ' || s[i] == '\t')) {
      i++;
    }
    if (i >= s.length || s[i] == '#') break;
    final b = StringBuffer();
    while (i < s.length && s[i] != ' ' && s[i] != '\t') {
      if (s[i] == '"') {
        final end = s.indexOf('"', i + 1);
        if (end < 0) {
          b.write(s.substring(i + 1));
          i = s.length;
        } else {
          b.write(s.substring(i + 1, end));
          i = end + 1;
        }
      } else {
        b.write(s[i]);
        i++;
      }
    }
    out.add(b.toString());
  }
  return out;
}

final _magic = RegExp(r'^#\s*sshsync(\s+.*)?$', caseSensitive: false);
final _magicGroup = RegExp(r'(?:^|\s)group=(?:"([^"]*)"|(\S*))');
final _magicTags = RegExp(r'(?:^|\s)tags=(?:"([^"]*)"|(\S*))');
final _keyword = RegExp(r'^([A-Za-z0-9]+)(?:[ \t]*=[ \t]*|[ \t]+)(.*)$');

/// Parses an OpenSSH client config. `Match` blocks and `Include` are ignored.
List<ImportedHost> parseSshConfig(String text) {
  final blocks = <_Block>[_Block(null)];
  final aliases = <String>[];
  _Block? current = blocks.first; // null while inside a Match block

  for (final raw in const LineSplitter().convert(text)) {
    final line = raw.trim();
    if (line.isEmpty) continue;
    if (line.startsWith('#')) {
      final m = _magic.firstMatch(line);
      if (m != null && current != null && current.patterns != null) {
        final rest = m.group(1) ?? '';
        final g = _magicGroup.firstMatch(rest);
        if (g != null) {
          final v = (g.group(1) ?? g.group(2) ?? '').trim();
          if (v.isNotEmpty) current.group ??= v;
        }
        final t = _magicTags.firstMatch(rest);
        if (t != null) {
          current.tags ??= (t.group(1) ?? t.group(2) ?? '')
              .split(',')
              .map((e) => e.trim())
              .where((e) => e.isNotEmpty)
              .toList();
        }
      }
      continue;
    }
    final m = _keyword.firstMatch(line);
    if (m == null) continue;
    final key = m.group(1)!.toLowerCase();
    final args = _tokens(m.group(2)!);
    if (key == 'match') {
      current = null;
      continue;
    }
    if (key == 'host') {
      current = _Block(args);
      blocks.add(current);
      for (final a in args) {
        if (!_isPattern(a) && !aliases.contains(a)) aliases.add(a);
      }
      continue;
    }
    if (current == null || args.isEmpty) continue;
    // First obtained value wins, also within a block.
    current.options.putIfAbsent(key, () => args.first);
  }

  final hosts = <ImportedHost>[];
  for (final alias in aliases) {
    final opts = <String, String>{};
    String? group;
    List<String>? tags;
    for (final b in blocks) {
      if (!b.matches(alias)) continue;
      b.options.forEach((k, v) => opts.putIfAbsent(k, () => v));
      if (b.lists(alias)) {
        group ??= b.group;
        tags ??= b.tags;
      }
    }
    final port = int.tryParse(opts['port'] ?? '');
    final user = opts['user'];
    hosts.add(ImportedHost(
      nickname: alias,
      hostname: _expandHostName(opts['hostname'], alias),
      port: (port != null && port > 0 && port < 65536) ? port : 22,
      user: (user == null || user.isEmpty) ? null : user,
      identityFile: _identity(opts['identityfile']),
      proxyJump: _firstHop(opts['proxyjump']),
      group: group,
      tags: List.of(tags ?? const <String>[]),
    ));
  }
  return hosts;
}

String _expandHostName(String? value, String alias) {
  if (value == null || value.isEmpty) return alias;
  return value.replaceAllMapped(
      RegExp(r'%([%h])'), (m) => m.group(1) == 'h' ? alias : '%');
}

String? _identity(String? v) =>
    (v == null || v.isEmpty || v.toLowerCase() == 'none') ? null : v;

String? _firstHop(String? value) {
  if (value == null) return null;
  var hop = value.split(',').first.trim();
  if (hop.isEmpty || hop.toLowerCase() == 'none') return null;
  final t = parseQuickConnect(hop);
  if (t != null) return t.host;
  // Not something we can parse; strip what we can.
  final at = hop.lastIndexOf('@');
  if (at >= 0) hop = hop.substring(at + 1);
  return hop.isEmpty ? null : hop;
}

/// Maps one PuTTY registry session (values keyed by PuTTY's registry value
/// names) to a host. Returns null unless it is an SSH session with a host.
ImportedHost? fromPuttySession(String sessionName, Map<String, Object?> values) {
  final protocol = values['Protocol'];
  if (protocol is! String || protocol.trim().toLowerCase() != 'ssh') {
    return null;
  }
  final rawHost = values['HostName'];
  if (rawHost is! String) return null;
  var host = rawHost.trim();
  String? user;
  final at = host.lastIndexOf('@');
  if (at >= 0) {
    user = host.substring(0, at);
    host = host.substring(at + 1);
  }
  if (host.isEmpty) return null;

  final userName = values['UserName'];
  if (userName is String && userName.trim().isNotEmpty) {
    user = userName.trim();
  }
  if (user != null && user.isEmpty) user = null;

  final rawPort = values['PortNumber'];
  final port = rawPort is int
      ? rawPort
      : (rawPort is String ? int.tryParse(rawPort.trim()) : null);

  final keyFile = values['PublicKeyFile'];
  final nickname = _decodePuttyName(sessionName);
  return ImportedHost(
    nickname: nickname.isEmpty ? host : nickname,
    hostname: host,
    port: (port != null && port > 0 && port < 65536) ? port : 22,
    user: user,
    identityFile:
        (keyFile is String && keyFile.trim().isNotEmpty) ? keyFile.trim() : null,
  );
}

/// PuTTY percent-encodes session names byte-wise in the registry.
String _decodePuttyName(String name) {
  final bytes = <int>[];
  var allAscii = true;
  for (var i = 0; i < name.length; i++) {
    final c = name.codeUnitAt(i);
    if (c == 0x25 && i + 2 < name.length) {
      final v = int.tryParse(name.substring(i + 1, i + 3), radix: 16);
      if (v != null) {
        bytes.add(v);
        i += 2;
        continue;
      }
    }
    if (c > 0x7f) allAscii = false;
    bytes.add(c);
  }
  if (!allAscii) {
    // Already contains non-ASCII characters; only decode ASCII escapes.
    return String.fromCharCodes(bytes).trim();
  }
  try {
    return utf8.decode(bytes).trim();
  } on FormatException {
    return latin1.decode(bytes).trim();
  }
}

/// Result of [parseQuickConnect].
class QuickTarget {
  String? user;
  String host;
  int port;
  QuickTarget({this.user, required this.host, this.port = 22});

  @override
  String toString() => 'QuickTarget(${user == null ? '' : '$user@'}$host:$port)';
}

final _hostChars = RegExp(r'^[^\s/\\@:\[\]#?]+$');
final _ipv6Chars = RegExp(r'^[0-9A-Fa-f:.]+(%[A-Za-z0-9._-]+)?$');

/// Parses `host`, `user@host`, `host:port`, `user@host:port`,
/// `ssh://user@host:port`, `[v6]:port` and bare IPv6 (no port).
/// Returns null for empty or invalid input.
QuickTarget? parseQuickConnect(String input) {
  var s = input.trim();
  if (s.isEmpty) return null;
  if (s.length >= 6 && s.substring(0, 6).toLowerCase() == 'ssh://') {
    s = s.substring(6);
    while (s.endsWith('/')) {
      s = s.substring(0, s.length - 1);
    }
  }
  if (s.isEmpty || RegExp(r'\s').hasMatch(s)) return null;

  String? user;
  final at = s.lastIndexOf('@');
  if (at >= 0) {
    user = s.substring(0, at);
    s = s.substring(at + 1);
    if (user.isEmpty || user.contains('/') || user.contains(':')) return null;
  }
  if (s.isEmpty) return null;

  String host;
  String? portText;
  if (s.startsWith('[')) {
    final end = s.indexOf(']');
    if (end < 0) return null;
    host = s.substring(1, end);
    final rest = s.substring(end + 1);
    if (rest.isNotEmpty) {
      if (!rest.startsWith(':')) return null;
      portText = rest.substring(1);
    }
    if (!host.contains(':') || !_ipv6Chars.hasMatch(host)) return null;
  } else {
    final colons = ':'.allMatches(s).length;
    if (colons >= 2) {
      host = s;
      if (!_ipv6Chars.hasMatch(host)) return null;
    } else {
      if (colons == 1) {
        final c = s.indexOf(':');
        host = s.substring(0, c);
        portText = s.substring(c + 1);
      } else {
        host = s;
      }
      if (!_hostChars.hasMatch(host)) return null;
    }
  }

  var port = 22;
  if (portText != null) {
    if (!RegExp(r'^[0-9]{1,5}$').hasMatch(portText)) return null;
    port = int.parse(portText);
    if (port < 1 || port > 65535) return null;
  }
  return QuickTarget(user: user, host: host, port: port);
}
