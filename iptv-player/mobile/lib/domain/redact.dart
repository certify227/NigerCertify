final secretKey = RegExp(
  r'pass(word|wd)?|secret|token|authorization|cookie|credential|api[-_]?key',
  caseSensitive: false,
);

final _userInfo = RegExp(
  r'([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@',
  caseSensitive: false,
);

final _secretQuery = RegExp(
  r'([?&](?:password|passwd|token|secret|apikey|api_key)=)[^&#\s]+',
  caseSensitive: false,
);

const _maxDepth = 6;
const _maxKeys = 40;

String redactText(String value) {
  final withoutUserInfo = value.replaceAllMapped(_userInfo, (match) => '${match[1]}[redacted]@');
  return withoutUserInfo.replaceAllMapped(_secretQuery, (match) => '${match[1]}[redacted]');
}

Object? redact(Object? value, [int depth = 0]) {
  if (depth > _maxDepth) return '[depth]';
  if (value is String) return redactText(value);
  if (value == null || value is num || value is bool) return value;
  if (value is Error || value is Exception) {
    return {'name': value.runtimeType.toString(), 'message': redactText(value.toString())};
  }
  if (value is List) {
    return [for (final item in value) redact(item as Object?, depth + 1)];
  }
  if (value is Map) {
    if (value.length > _maxKeys) return '[object]';
    return {
      for (final entry in value.entries)
        entry.key.toString(): secretKey.hasMatch(entry.key.toString())
            ? '[redacted]'
            : redact(entry.value as Object?, depth + 1),
    };
  }
  return redactText(value.toString());
}
