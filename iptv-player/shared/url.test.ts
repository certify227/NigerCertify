import { describe, expect, it } from 'vitest'
import { parseHttpUrl } from './url'

describe('parseHttpUrl', () => {
  it('accepte une URL http ou https sans identifiant', () => {
    expect(parseHttpUrl(' https://example.com/playlist.m3u ')).toEqual({
      ok: true,
      url: 'https://example.com/playlist.m3u',
    })
    expect(parseHttpUrl('http://192.168.1.20:8080/live.m3u8').ok).toBe(true)
    expect(parseHttpUrl('http://localhost:8080/playlist.m3u').ok).toBe(true)
  })

  it('refuse les protocoles interdits et les mots de passe dans l URL', () => {
    for (const input of [
      'javascript:alert(1)',
      'file:///tmp/playlist.m3u',
      'ftp://example.com/a.m3u',
      'https://user:secret@example.com/playlist.m3u',
      'pas une url',
      '',
    ]) {
      const result = parseHttpUrl(input)
      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.message).toBe(
          'Adresse invalide. Utilisez une URL http ou https sans identifiant.',
        )
        expect(result.message).not.toContain('secret')
      }
    }
  })
})
