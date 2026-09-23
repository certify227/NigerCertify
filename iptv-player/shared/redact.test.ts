import { describe, expect, it } from 'vitest'
import { redact, redactText } from './redact'

describe('redact', () => {
  it('masque les mots de passe et les jetons dans les objets', () => {
    const sanitized = redact({
      username: 'salon',
      password: 'super-secret',
      apiKey: 'token-value',
      nested: { authorization: 'Bearer hidden' },
    })

    expect(JSON.stringify(sanitized)).not.toContain('super-secret')
    expect(JSON.stringify(sanitized)).not.toContain('token-value')
    expect(JSON.stringify(sanitized)).not.toContain('Bearer hidden')
    expect(sanitized).toMatchObject({
      username: 'salon',
      password: '[redacted]',
      apiKey: '[redacted]',
      nested: { authorization: '[redacted]' },
    })
  })

  it('retire les identifiants présents dans une URL', () => {
    const text = redactText('https://alice:s3cret@example.com/live/a.m3u8?password=hidden&x=1')
    expect(text).not.toContain('s3cret')
    expect(text).not.toContain('hidden')
    expect(text).toContain('https://[redacted]@example.com/live/a.m3u8?password=[redacted]&x=1')
  })
})
