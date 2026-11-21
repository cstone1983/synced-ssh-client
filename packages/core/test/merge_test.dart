import 'dart:math';

import 'package:sshsync_core/sshsync_core.dart';
import 'package:test/test.dart';

String ck(int ms, String dev, [int n = 0]) =>
    '${ms.toRadixString(16).padLeft(12, '0')}-${n.toRadixString(16).padLeft(4, '0')}-$dev';

RecState rec(Map<String, (Object?, String)> f, {String? deleted}) => RecState(
    'r', 'host', {for (final e in f.entries) e.key: e.value.$1},
    {for (final e in f.entries) e.key: e.value.$2},
    deleted: deleted);

void main() {
  group('hlc', () {
    test('is monotonic even when the wall clock goes backwards', () {
      var now = 1000;
      final h = Hlc('a', now: () => now);
      final c1 = h.next();
      now = 500;
      final c2 = h.next();
      final c3 = h.next();
      expect(c2.compareTo(c1) > 0, isTrue);
      expect(c3.compareTo(c2) > 0, isTrue);
    });
    test('moves past observed clocks', () {
      final h = Hlc('a', now: () => 1000);
      h.observe(ck(9000, 'b', 7));
      expect(h.next().compareTo(ck(9000, 'b', 7)) > 0, isTrue);
      expect(Hlc.wallMs(ck(9000, 'b')), 9000);
      expect(Hlc.deviceOf(ck(9000, 'dev-b')), 'dev-b');
    });
    test('survives restart via last clock', () {
      final h = Hlc('a', now: () => 5000);
      final last = h.next();
      final h2 = Hlc('a', now: () => 100, last: last);
      expect(h2.next().compareTo(last) > 0, isTrue);
    });
  });

  group('merge', () {
    final base = {'name': ck(1, 'a'), 'port': ck(1, 'a')};

    test('no local record: take remote', () {
      final r = rec({'name': ('x', ck(1, 'a'))});
      final m = mergeRecords(null, r, {});
      expect(m.state.fields, {'name': 'x'});
      expect(m.needsPush, isFalse);
      expect(m.conflicts, isEmpty);
    });

    test('identical: nothing to do', () {
      final a = rec({'name': ('x', ck(1, 'a')), 'port': (22, ck(1, 'a'))});
      final m = mergeRecords(a, a, base);
      expect(m.needsPush, isFalse);
      expect(m.changedLocal, isFalse);
    });

    test('only remote changed: take remote, no conflict', () {
      final l = rec({'name': ('x', ck(1, 'a')), 'port': (22, ck(1, 'a'))});
      final r = rec({'name': ('y', ck(5, 'b')), 'port': (22, ck(1, 'a'))});
      final m = mergeRecords(l, r, base);
      expect(m.state.fields['name'], 'y');
      expect(m.conflicts, isEmpty);
      expect(m.needsPush, isFalse);
    });

    test('only local changed: keep local, push', () {
      final l = rec({'name': ('z', ck(5, 'a')), 'port': (22, ck(1, 'a'))});
      final r = rec({'name': ('x', ck(1, 'a')), 'port': (22, ck(1, 'a'))});
      final m = mergeRecords(l, r, base);
      expect(m.state.fields['name'], 'z');
      expect(m.conflicts, isEmpty);
      expect(m.needsPush, isTrue);
    });

    test('different fields changed on each side: both kept, no conflict', () {
      final l = rec({'name': ('L', ck(5, 'a')), 'port': (22, ck(1, 'a'))});
      final r = rec({'name': ('x', ck(1, 'a')), 'port': (2222, ck(6, 'b'))});
      final m = mergeRecords(l, r, base);
      expect(m.state.fields, {'name': 'L', 'port': 2222});
      expect(m.conflicts, isEmpty);
      expect(m.needsPush, isTrue);
    });

    test('same field changed on both: later wins, loser recorded', () {
      final l = rec({'name': ('L', ck(5, 'a')), 'port': (22, ck(1, 'a'))});
      final r = rec({'name': ('R', ck(9, 'b')), 'port': (22, ck(1, 'a'))});
      final m = mergeRecords(l, r, base);
      expect(m.state.fields['name'], 'R');
      expect(m.conflicts, hasLength(1));
      expect(m.conflicts.single.field, 'name');
      expect(m.conflicts.single.winningValue, 'R');
      expect(m.conflicts.single.losingValue, 'L');

      final m2 = mergeRecords(
          rec({'name': ('L', ck(20, 'a')), 'port': (22, ck(1, 'a'))}), r, base);
      expect(m2.state.fields['name'], 'L');
      expect(m2.conflicts.single.losingValue, 'R');
      expect(m2.needsPush, isTrue);
    });

    test('same field changed to the same value: no conflict', () {
      final l = rec({'name': ('S', ck(5, 'a')), 'port': (22, ck(1, 'a'))});
      final r = rec({'name': ('S', ck(9, 'b')), 'port': (22, ck(1, 'a'))});
      final m = mergeRecords(l, r, base);
      expect(m.conflicts, isEmpty);
      expect(m.state.clocks['name'], ck(9, 'b'));
    });

    test('equal wall time: device id breaks the tie deterministically', () {
      final l = rec({'name': ('L', ck(5, 'a')), 'port': (22, ck(1, 'a'))});
      final r = rec({'name': ('R', ck(5, 'b')), 'port': (22, ck(1, 'a'))});
      expect(mergeRecords(l, r, base).state.fields['name'], 'R');
      expect(mergeRecords(r, l, base).state.fields['name'], 'R');
    });

    test('list-valued field merges as one value', () {
      final l = rec({'tags': (['a', 'b'], ck(5, 'a'))});
      final r = rec({'tags': (['c'], ck(9, 'b'))});
      final m = mergeRecords(l, r, {'tags': ck(1, 'a')});
      expect(m.state.fields['tags'], ['c']);
      expect(m.conflicts.single.losingValue, ['a', 'b']);
    });

    test('replayed old version from the server changes nothing', () {
      final l = rec({'name': ('new', ck(9, 'a')), 'port': (22, ck(1, 'a'))});
      final old = rec({'name': ('old', ck(1, 'a')), 'port': (22, ck(1, 'a'))});
      final m = mergeRecords(l, old, {'name': ck(9, 'a'), 'port': ck(1, 'a')});
      expect(m.state.fields['name'], 'new');
      expect(m.changedLocal, isFalse);
    });

    test('remote delete, local untouched: deleted, no conflict', () {
      final l = rec({'name': ('x', ck(1, 'a')), 'port': (22, ck(1, 'a'))});
      final r = rec({}, deleted: ck(5, 'b'));
      final m = mergeRecords(l, RecState('r', 'host', {}, base, deleted: ck(5, 'b')), base);
      expect(m.state.isDeleted, isTrue);
      expect(m.state.fields, isEmpty);
      expect(m.conflicts, isEmpty);
      expect(r.isDeleted, isTrue);
    });

    test('remote delete vs local edit: delete wins, edit kept as conflict', () {
      final l = rec({'name': ('edited', ck(7, 'a')), 'port': (22, ck(1, 'a'))});
      final r = RecState('r', 'host', {}, base, deleted: ck(5, 'b'));
      final m = mergeRecords(l, r, base);
      expect(m.state.isDeleted, isTrue);
      expect(m.conflicts.single.kind, 'delete');
      expect(m.conflicts.single.snapshot, {'name': 'edited', 'port': 22});
    });

    test('local delete vs remote edit: delete wins, edit kept as conflict', () {
      final l = RecState('r', 'host', {}, base, deleted: ck(5, 'a'));
      final r = rec({'name': ('edited', ck(7, 'b')), 'port': (22, ck(1, 'a'))});
      final m = mergeRecords(l, r, base);
      expect(m.state.isDeleted, isTrue);
      expect(m.needsPush, isTrue);
      expect(m.conflicts.single.snapshot!['name'], 'edited');
    });

    test('random edits on three replicas converge regardless of merge order', () {
      final rnd = Random(42);
      for (var round = 0; round < 200; round++) {
        final fields = ['a', 'b', 'c', 'd'];
        var t = 10;
        RecState make(String dev) {
          final f = <String, (Object?, String)>{};
          for (final k in fields) {
            if (rnd.nextBool()) f[k] = (rnd.nextInt(5), ck(t += rnd.nextInt(3), dev));
          }
          return rec(f, deleted: rnd.nextInt(8) == 0 ? ck(t++, dev) : null);
        }

        final x = make('x'), y = make('y'), z = make('z');
        RecState m(RecState p, RecState q) => mergeRecords(p, q, {}).state;
        final r1 = m(m(x, y), z), r2 = m(x, m(y, z)), r3 = m(m(z, x), y);
        expect(r1.encode(), r2.encode());
        expect(canonicalJson(r1.fields), canonicalJson(r3.fields));
        expect(canonicalJson(r1.clocks), canonicalJson(r3.clocks));
        expect(r1.deleted, r3.deleted);
        expect(m(r1, r1).encode(), r1.encode(), reason: 'idempotent');
      }
    });
  });
}
