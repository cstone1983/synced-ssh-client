import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';

/// The running Windows build's version. CI passes it with
/// --dart-define=APP_VERSION=... (the windows-v tag, or pubspec's version on
/// branch builds). A local `flutter run` has none.
const appVersion = String.fromEnvironment('APP_VERSION', defaultValue: 'dev');

bool get isDevBuild => !RegExp(r'^\d+(\.\d+)*').hasMatch(appVersion);

/// A newer Windows release found on GitHub.
class WindowsUpdate {
  final String version;
  final String fileName;
  final Uri installer;
  final Uri checksum;
  const WindowsUpdate(this.version, this.fileName, this.installer, this.checksum);
}

class UpdateException implements Exception {
  final String message;
  const UpdateException(this.message);
  @override
  String toString() => message;
}

/// Windows self-update from this repo's GitHub releases (windows-v* tags,
/// published by CI with the installer and its SHA-256). Android updates come
/// from the app store instead.
class Updater {
  static const repo = 'cstone1983/synced-ssh-client';
  static const _tagPrefix = 'windows-v';

  /// Compares dotted versions: 0.10.0 > 0.9.1, and 1.0.0 > 1.0.0-beta1.
  static int compareVersions(String a, String b) {
    (List<int>, String) parse(String v) {
      final dash = v.indexOf('-');
      final core = dash < 0 ? v : v.substring(0, dash);
      final pre = dash < 0 ? '' : v.substring(dash + 1);
      return ([for (final p in core.split('.')) int.tryParse(p) ?? 0], pre);
    }

    final (na, pa) = parse(a);
    final (nb, pb) = parse(b);
    for (var i = 0; i < (na.length > nb.length ? na.length : nb.length); i++) {
      final x = i < na.length ? na[i] : 0, y = i < nb.length ? nb[i] : 0;
      if (x != y) return x.compareTo(y);
    }
    if (pa == pb) return 0;
    if (pa.isEmpty) return 1; // a release beats its own pre-release
    if (pb.isEmpty) return -1;
    return pa.compareTo(pb);
  }

  /// Picks the newest published, non-pre-release windows-v* release that
  /// is newer than [current] and has both the installer and its .sha256.
  static WindowsUpdate? pickUpdate(List<dynamic> releases, String current) {
    WindowsUpdate? best;
    for (final r in releases) {
      if (r is! Map) continue;
      final tag = r['tag_name'];
      if (tag is! String || !tag.startsWith(_tagPrefix)) continue;
      if (r['draft'] == true || r['prerelease'] == true) continue;
      final version = tag.substring(_tagPrefix.length);
      if (!RegExp(r'^\d+(\.\d+)*$').hasMatch(version)) continue;
      if (compareVersions(version, current) <= 0) continue;
      if (best != null && compareVersions(version, best.version) <= 0) continue;
      final assets = {
        for (final a in (r['assets'] as List? ?? const []))
          if (a is Map && a['name'] is String && a['browser_download_url'] is String)
            a['name'] as String: a['browser_download_url'] as String,
      };
      final exe = assets.keys.where((n) => n.startsWith('sshsync-setup-') && n.endsWith('.exe')).firstOrNull;
      if (exe == null || assets['$exe.sha256'] == null) continue;
      final exeUrl = Uri.parse(assets[exe]!), sumUrl = Uri.parse(assets['$exe.sha256']!);
      if (exeUrl.scheme != 'https' || sumUrl.scheme != 'https') continue;
      best = WindowsUpdate(version, exe, exeUrl, sumUrl);
    }
    return best;
  }

  /// Reads the expected hash from a `sha256sum`-style line.
  static String? parseChecksum(String text) =>
      RegExp(r'\b([0-9a-fA-F]{64})\b').firstMatch(text)?.group(1)?.toLowerCase();

  static HttpClient _client() => HttpClient()
    ..connectionTimeout = const Duration(seconds: 15)
    ..userAgent = 'sshsync-windows-updater';

  static Future<List<int>> _get(HttpClient c, Uri url, {int? maxBytes, bool api = false}) async {
    final req = await c.getUrl(url);
    if (api) req.headers.set(HttpHeaders.acceptHeader, 'application/vnd.github+json');
    final res = await req.close().timeout(const Duration(seconds: 30));
    if (res.statusCode != 200) {
      await res.drain<void>();
      throw UpdateException('GitHub answered ${res.statusCode}.');
    }
    final out = BytesBuilder(copy: false);
    await for (final chunk in res.timeout(const Duration(seconds: 30))) {
      out.add(chunk);
      if (maxBytes != null && out.length > maxBytes) throw const UpdateException('Unexpectedly large reply.');
    }
    return out.takeBytes();
  }

  /// Null when this build is the newest (or a development build).
  static Future<WindowsUpdate?> check() async {
    if (isDevBuild) return null;
    final c = _client();
    try {
      final body = await _get(c, Uri.parse('https://api.github.com/repos/$repo/releases?per_page=30'),
          maxBytes: 4 << 20, api: true);
      final list = jsonDecode(utf8.decode(body));
      return list is List ? pickUpdate(list, appVersion) : null;
    } finally {
      c.close(force: true);
    }
  }

  /// Downloads the installer to a temp folder and checks it against the
  /// SHA-256 published with the release. Throws [UpdateException] on a
  /// mismatch (the file is deleted).
  static Future<File> download(WindowsUpdate u, {void Function(double? progress)? onProgress}) async {
    final c = _client();
    final dir = Directory('${Directory.systemTemp.path}${Platform.pathSeparator}sshsync-update');
    final file = File('${dir.path}${Platform.pathSeparator}${u.fileName}');
    try {
      final expected = parseChecksum(utf8.decode(await _get(c, u.checksum, maxBytes: 4096)));
      if (expected == null) throw const UpdateException('The release has no readable checksum.');
      dir.createSync(recursive: true);
      if (file.existsSync()) file.deleteSync();

      final req = await c.getUrl(u.installer);
      final res = await req.close().timeout(const Duration(seconds: 30));
      if (res.statusCode != 200) {
        await res.drain<void>();
        throw UpdateException('Download failed (${res.statusCode}).');
      }
      final total = res.contentLength;
      final digest = SHA256Digest();
      final sink = file.openWrite();
      var got = 0;
      try {
        await for (final chunk in res.timeout(const Duration(seconds: 60))) {
          final bytes = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
          digest.update(bytes, 0, bytes.length);
          sink.add(bytes);
          got += bytes.length;
          if (got > 512 << 20) throw const UpdateException('The installer is unexpectedly large.');
          onProgress?.call(total > 0 ? got / total : null);
        }
      } finally {
        await sink.close();
      }
      final out = Uint8List(digest.digestSize);
      digest.doFinal(out, 0);
      final actual = out.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      if (actual != expected) {
        throw const UpdateException('The download does not match its published checksum, so it was not run.');
      }
      return file;
    } catch (e) {
      if (file.existsSync()) {
        try {
          file.deleteSync();
        } catch (_) {}
      }
      if (e is UpdateException) rethrow;
      throw UpdateException('Download failed: $e');
    } finally {
      c.close(force: true);
    }
  }

  /// Starts the installer (it replaces this install in place and reopens the
  /// app) and quits so the files can be replaced.
  static Future<Never> install(File installer) async {
    await Process.start(installer.path, const ['/SILENT', '/SP-', '/NOCANCEL', '/UPDATE=1'],
        mode: ProcessStartMode.detached);
    exit(0);
  }
}
