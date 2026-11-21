import 'package:sshsync_core/src/import/hosts_import.dart';
import 'package:test/test.dart';

void main() {
  group('parseSshConfig', () {
    test('basic blocks, defaults and keyword forms', () {
      final hosts = parseSshConfig('''
# a comment
Host web
    HostName 10.0.0.5
    Port 2222
    User deploy
    IdentityFile ~/.ssh/id_web
    IdentityFile ~/.ssh/second

host=db
  hostname = db.internal.example.com
  USER="db admin"
  identityfile "C:\\Users\\me\\my keys\\db.pem"   # trailing comment

Host plain

Host *
    User fallback
    Port 2200
    IdentityFile ~/.ssh/id_default
''');
      expect(hosts.map((h) => h.nickname), ['web', 'db', 'plain']);

      final web = hosts[0];
      expect(web.hostname, '10.0.0.5');
      expect(web.port, 2222);
      expect(web.user, 'deploy');
      expect(web.identityFile, '~/.ssh/id_web');
      expect(web.proxyJump, isNull);
      expect(web.group, isNull);
      expect(web.tags, isEmpty);

      final db = hosts[1];
      expect(db.hostname, 'db.internal.example.com');
      expect(db.user, 'db admin');
      expect(db.port, 2200);
      expect(db.identityFile, r'C:\Users\me\my keys\db.pem');

      final plain = hosts[2];
      expect(plain.hostname, 'plain');
      expect(plain.user, 'fallback');
      expect(plain.port, 2200);
      expect(plain.identityFile, '~/.ssh/id_default');
    });

    test('no Host * means port 22 and no user', () {
      final h = parseSshConfig('Host a\n').single;
      expect(h.hostname, 'a');
      expect(h.port, 22);
      expect(h.user, isNull);
      expect(h.identityFile, isNull);
    });

    test('several aliases, patterns skipped, first match wins', () {
      final hosts = parseSshConfig('''
User early

Host *.example.com !bad.example.com
    User wild
    Port 2022

Host a.example.com bad.example.com other ?x *
    HostName %h.internal
    User specific
    Port 22022

Host other
    HostName never-used
    ProxyJump jump

Host a.example.com
    IdentityFile ~/.ssh/late
''');
      expect(hosts.map((h) => h.nickname),
          ['a.example.com', 'bad.example.com', 'other']);
      // Global section comes first, so its User wins everywhere.
      expect(hosts.every((h) => h.user == 'early'), isTrue);

      expect(hosts[0].port, 2022); // from the earlier wildcard block
      expect(hosts[0].hostname, 'a.example.com.internal');
      expect(hosts[0].identityFile, '~/.ssh/late'); // merged from later block

      expect(hosts[1].port, 22022); // negated in the wildcard block
      expect(hosts[2].port, 22022);
      expect(hosts[2].hostname, 'other.internal');
      expect(hosts[2].proxyJump, 'jump');
    });

    test('ProxyJump forms', () {
      String? pj(String v) =>
          parseSshConfig('Host a\n  ProxyJump $v\n').single.proxyJump;
      expect(pj('bastion'), 'bastion');
      expect(pj('admin@bastion'), 'bastion');
      expect(pj('admin@bastion.example.com:2222'), 'bastion.example.com');
      expect(pj('u@first:22,u2@second:23'), 'first');
      expect(pj('ssh://admin@gw.example.com:2200'), 'gw.example.com');
      expect(pj('[2001:db8::1]:22'), '2001:db8::1');
      expect(pj('none'), isNull);
    });

    test('Match blocks and Include are ignored', () {
      final hosts = parseSshConfig('''
Include ~/.ssh/config.d/*
Host a
    User one
Match host a exec "true"
    User matched
    Port 99
    HostName evil
Host b
    Include other
    Port 23
''');
      expect(hosts.map((h) => h.nickname), ['a', 'b']);
      expect(hosts[0].user, 'one');
      expect(hosts[0].port, 22);
      expect(hosts[0].hostname, 'a');
      expect(hosts[1].user, isNull);
      expect(hosts[1].port, 23);
    });

    test('sshsync magic comment', () {
      final hosts = parseSshConfig('''
#sshsync group=ignored-outside-block
Host a
    #sshsync group=Work tags=prod,web, eu
    HostName a.example
Host b
    # sshsync tags=solo
Host c
    #sshsync group="Home Lab"
Host d
    #sshsync tags="x, y z" group="Two Words"
Host e f
    #SSHSYNC group=shared
    # sshsyncfoo group=nope
Host g
    # just a comment about sshsync group=nope
Host *
    #sshsync group=star tags=star
''');
      final by = {for (final h in hosts) h.nickname: h};
      expect(by.keys, ['a', 'b', 'c', 'd', 'e', 'f', 'g']);
      expect(by['a']!.group, 'Work');
      expect(by['a']!.tags, ['prod', 'web']);
      expect(by['a']!.hostname, 'a.example');
      expect(by['b']!.group, isNull);
      expect(by['b']!.tags, ['solo']);
      expect(by['c']!.group, 'Home Lab');
      expect(by['c']!.tags, isEmpty);
      expect(by['d']!.group, 'Two Words');
      expect(by['d']!.tags, ['x', 'y z']);
      expect(by['e']!.group, 'shared');
      expect(by['f']!.group, 'shared');
      expect(by['g']!.group, isNull);
      expect(by['g']!.tags, isEmpty);
    });

    test('robust against junk', () {
      expect(parseSshConfig(''), isEmpty);
      expect(parseSshConfig('garbage\n\n=\nHost\nPort\n'), isEmpty);
      final h = parseSshConfig('Host a\r\n  Port abc\r\n  User  bob  \r\n').single;
      expect(h.port, 22);
      expect(h.user, 'bob');
      expect(parseSshConfig('Host a\n  Port 70000\n').single.port, 22);
      // Duplicate aliases collapse into one host.
      expect(parseSshConfig('Host a\nHost a\n  User x\n').single.user, 'x');
    });
  });

  group('fromPuttySession', () {
    test('maps an SSH session', () {
      final h = fromPuttySession('My%20Server', {
        'HostName': 'example.com',
        'PortNumber': 2222,
        'UserName': 'alice',
        'PublicKeyFile': r'C:\keys\id.ppk',
        'Protocol': 'ssh',
      })!;
      expect(h.nickname, 'My Server');
      expect(h.hostname, 'example.com');
      expect(h.port, 2222);
      expect(h.user, 'alice');
      expect(h.identityFile, r'C:\keys\id.ppk');
      expect(h.proxyJump, isNull);
      expect(h.tags, isEmpty);
    });

    test('user@host, defaults and empties', () {
      final h = fromPuttySession('box', {
        'HostName': 'bob@10.1.2.3',
        'UserName': '',
        'PublicKeyFile': '',
        'Protocol': 'ssh',
      })!;
      expect(h.hostname, '10.1.2.3');
      expect(h.user, 'bob');
      expect(h.port, 22);
      expect(h.identityFile, isNull);

      // UserName wins over the user@ prefix.
      final h2 = fromPuttySession('box', {
        'HostName': 'bob@host',
        'UserName': 'carol',
        'Protocol': 'ssh',
      })!;
      expect(h2.user, 'carol');
      expect(h2.hostname, 'host');
    });

    test('percent decoding', () {
      Map<String, Object?> v() => {'HostName': 'h', 'Protocol': 'ssh'};
      expect(fromPuttySession('caf%C3%A9%20%2F%20prod', v())!.nickname,
          'café / prod');
      expect(fromPuttySession('caf%E9', v())!.nickname, 'café'); // legacy codepage
      expect(fromPuttySession('100%', v())!.nickname, '100%');
      expect(fromPuttySession('a%zzb', v())!.nickname, 'a%zzb');
    });

    test('returns null for non-SSH or host-less sessions', () {
      expect(fromPuttySession('t', {'HostName': 'h', 'Protocol': 'telnet'}), isNull);
      expect(fromPuttySession('s', {'HostName': 'COM1', 'Protocol': 'serial'}), isNull);
      expect(fromPuttySession('Default%20Settings', {'HostName': '', 'Protocol': 'ssh'}), isNull);
      expect(fromPuttySession('x', {'Protocol': 'ssh'}), isNull);
      expect(fromPuttySession('x', {'HostName': 'h'}), isNull);
      expect(fromPuttySession('x', {'HostName': 'user@', 'Protocol': 'ssh'}), isNull);
      expect(fromPuttySession('x', {'HostName': 5, 'Protocol': 'ssh'}), isNull);
    });
  });

  group('parseQuickConnect', () {
    void ok(String input, String? user, String host, int port) {
      final t = parseQuickConnect(input);
      expect(t, isNotNull, reason: input);
      expect(t!.user, user, reason: input);
      expect(t.host, host, reason: input);
      expect(t.port, port, reason: input);
    }

    test('accepted forms', () {
      ok('example.com', null, 'example.com', 22);
      ok('  example.com \n', null, 'example.com', 22);
      ok('root@example.com', 'root', 'example.com', 22);
      ok('example.com:2222', null, 'example.com', 2222);
      ok('root@10.0.0.1:2222', 'root', '10.0.0.1', 2222);
      ok('ssh://root@example.com:2222', 'root', 'example.com', 2222);
      ok('SSH://example.com/', null, 'example.com', 22);
      ok('[::1]:2222', null, '::1', 2222);
      ok('[::1]', null, '::1', 22);
      ok('me@[2001:db8::5]:22022', 'me', '2001:db8::5', 22022);
      ok('fe80::1', null, 'fe80::1', 22);
      ok('root@fe80::1%eth0', 'root', 'fe80::1%eth0', 22);
      ok('first.last@corp@host', 'first.last@corp', 'host', 22);
      ok('host:65535', null, 'host', 65535);
    });

    test('rejected forms', () {
      for (final bad in [
        '',
        '   ',
        'ssh://',
        'host name',
        'user name@host',
        'host:',
        'host:0',
        'host:65536',
        'host:abc',
        'host:-1',
        'host:22x',
        '@host',
        'user@',
        '[::1',
        '[::1]2222',
        '[::1]:',
        '[::1]:99999',
        '[notv6]:22',
        'gggg::1',
        'host/path',
        'http://example.com',
      ]) {
        expect(parseQuickConnect(bad), isNull, reason: '"$bad"');
      }
    });
  });
}
