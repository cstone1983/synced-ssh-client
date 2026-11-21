/// Hybrid logical clock. Clocks are fixed-width strings that sort
/// lexicographically: `<ms:12 hex>-<counter:4 hex>-<deviceId>`.
///
/// A device's clock never goes backwards and always moves past any clock it
/// has seen, so a wrong wall clock cannot make a device lose every merge.
class Hlc {
  final String deviceId;
  final int Function() _now;
  int _ms = 0;
  int _counter = 0;

  Hlc(this.deviceId, {int Function()? now, String? last})
      : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch) {
    if (last != null) observe(last);
  }

  String get current => _format(_ms, _counter);

  String next() {
    final now = _now();
    if (now > _ms) {
      _ms = now;
      _counter = 0;
    } else if (++_counter > 0xffff) {
      _ms++;
      _counter = 0;
    }
    return current;
  }

  /// Advance past a clock seen from another device.
  void observe(String clock) {
    final ms = wallMs(clock);
    final counter = int.parse(clock.substring(13, 17), radix: 16);
    if (ms > _ms || (ms == _ms && counter > _counter)) {
      _ms = ms;
      _counter = counter;
    }
  }

  String _format(int ms, int counter) =>
      '${ms.toRadixString(16).padLeft(12, '0')}-'
      '${counter.toRadixString(16).padLeft(4, '0')}-$deviceId';

  static int wallMs(String clock) => int.parse(clock.substring(0, 12), radix: 16);
  static String deviceOf(String clock) => clock.substring(18);
  static bool isValid(String clock) =>
      RegExp(r'^[0-9a-f]{12}-[0-9a-f]{4}-.+$').hasMatch(clock);
}

String? maxClock(String? a, String? b) {
  if (a == null) return b;
  if (b == null) return a;
  return a.compareTo(b) >= 0 ? a : b;
}
