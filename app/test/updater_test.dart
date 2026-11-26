import 'package:flutter_test/flutter_test.dart';
import 'package:sshsync/updater.dart';

Map<String, dynamic> release(String tag, {bool pre = false, bool draft = false, bool sum = true, String? exe}) {
  final v = tag.replaceFirst('windows-v', '');
  final name = exe ?? 'sshsync-setup-$v.exe';
  return {
    'tag_name': tag,
    'prerelease': pre,
    'draft': draft,
    'assets': [
      {'name': name, 'browser_download_url': 'https://github.com/x/releases/download/$tag/$name'},
      if (sum) {'name': '$name.sha256', 'browser_download_url': 'https://github.com/x/releases/download/$tag/$name.sha256'},
    ],
  };
}

void main() {
  test('version order', () {
    expect(Updater.compareVersions('0.10.0', '0.9.1'), greaterThan(0));
    expect(Updater.compareVersions('1.0', '1.0.0'), 0);
    expect(Updater.compareVersions('1.0.0', '1.0.0-beta1'), greaterThan(0));
    expect(Updater.compareVersions('0.1.0', '0.1.1'), lessThan(0));
  });

  test('picks the newest stable windows release that has a checksum', () {
    final list = [
      release('windows-v0.3.0', pre: true),
      release('windows-v0.2.5', draft: true),
      release('windows-v0.2.1', sum: false),
      release('windows-v0.2.0'),
      release('windows-v0.1.5'),
      release('android-v9.0.0'),
      release('windows-v0.1.0'),
    ];
    final u = Updater.pickUpdate(list, '0.1.0')!;
    expect(u.version, '0.2.0');
    expect(u.fileName, 'sshsync-setup-0.2.0.exe');
    expect(u.checksum.path, endsWith('sshsync-setup-0.2.0.exe.sha256'));
  });

  test('no update when current is newest', () {
    expect(Updater.pickUpdate([release('windows-v0.1.0')], '0.1.0'), isNull);
    expect(Updater.pickUpdate([release('windows-v0.1.0')], '0.2.0'), isNull);
    expect(Updater.pickUpdate([], '0.1.0'), isNull);
  });

  test('checksum line parsing', () {
    const h = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
    expect(Updater.parseChecksum('$h  sshsync-setup-0.1.0.exe\n'), h);
    expect(Updater.parseChecksum(h.toUpperCase()), h);
    expect(Updater.parseChecksum('nothing here'), isNull);
  });
}
