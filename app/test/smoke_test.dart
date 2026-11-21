import 'package:flutter_test/flutter_test.dart';
import 'package:sshsync/theme.dart';
import 'package:sshsync/ui/onboarding.dart';

void main() {
  test('passphrase strength grows with length and variety', () {
    expect(passphraseStrength('short'), 0);
    expect(passphraseStrength('elevenchars'), 0);
    expect(passphraseStrength('twelve chars'), greaterThan(0));
    expect(passphraseStrength('correct horse battery staple'), 3);
  });

  test('both app themes and every terminal theme build', () {
    expect(appTheme(true).colorScheme.primary, C.accent);
    expect(appTheme(false).brightness.name, 'light');
    expect(terminalThemes.keys, containsAll(['default', 'light']));
  });
}
