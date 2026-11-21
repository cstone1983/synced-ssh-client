import 'dart:convert';
import 'dart:typed_data';

void zero(Uint8List b) => b.fillRange(0, b.length, 0);

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Formats 16 bytes as a version-4-shaped UUID string.
String uuidFromBytes(Uint8List bytes) {
  final b = Uint8List.fromList(bytes.sublist(0, 16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  final h = _hex(b);
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-'
      '${h.substring(16, 20)}-${h.substring(20)}';
}

/// JSON with sorted keys, so structurally equal values encode identically.
String canonicalJson(Object? v) => jsonEncode(_canon(v));

Object? _canon(Object? v) {
  if (v is Map) {
    final keys = v.keys.map((k) => k.toString()).toList()..sort();
    return {for (final k in keys) k: _canon(v[k])};
  }
  if (v is List) return v.map(_canon).toList();
  return v;
}

bool deepEquals(Object? a, Object? b) => canonicalJson(a) == canonicalJson(b);
