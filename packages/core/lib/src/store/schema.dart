/// Record types and which of their fields are secret. Secret fields are
/// encrypted in the local database; everything is encrypted before sync.
class RecordType {
  static const host = 'host';
  static const credential = 'credential';
  static const group = 'group';
  static const knownHost = 'known_host';
  static const setting = 'setting';
  static const conflict = 'conflict';

  static const all = [host, credential, group, knownHost, setting, conflict];

  static const _secret = <String, Set<String>>{
    credential: {'password', 'private_key'},
    // Conflicts may hold a losing password or key, so their values are secret.
    conflict: {'winning_value', 'losing_value', 'snapshot'},
  };

  static bool isSecret(String type, String field) =>
      _secret[type]?.contains(field) ?? false;
}

class AuthOrder {
  static const keyThenPassword = 'key_then_password';
  static const keyOnly = 'key_only';
  static const passwordOnly = 'password_only';
  static const all = [keyThenPassword, keyOnly, passwordOnly];
}
