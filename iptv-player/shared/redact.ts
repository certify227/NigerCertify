const SECRET_KEY = /pass(word|wd)?|secret|token|authorization|cookie|credential|api[-_]?key/i
const USERINFO_PATTERN = /([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi
const SECRET_QUERY_PATTERN = /([?&](?:password|passwd|token|secret|apikey|api_key)=)[^&#\s]+/gi
const MAX_DEPTH = 6
const MAX_KEYS = 40

export function redactText(value: string): string {
  return value
    .replace(USERINFO_PATTERN, '$1[redacted]@')
    .replace(SECRET_QUERY_PATTERN, '$1[redacted]')
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) return '[depth]'
  if (typeof value === 'string') return redactText(value)
  if (typeof value !== 'object' || value === null) return value
  if (value instanceof Error) {
    return { name: value.name, message: redactText(value.message) }
  }
  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1))

  const entries = Object.entries(value)
  if (entries.length > MAX_KEYS) return '[object]'

  const output: Record<string, unknown> = {}
  for (const [key, nested] of entries) {
    output[key] = SECRET_KEY.test(key) ? '[redacted]' : redact(nested, depth + 1)
  }
  return output
}
