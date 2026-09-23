import { z } from 'zod'

const httpUrlSchema = z.url({ protocol: /^https?$/ }).refine((value) => {
  try {
    const url = new URL(value)
    return url.hostname.length > 0 && url.username.length === 0 && url.password.length === 0
  } catch {
    return false
  }
}, 'credentials')

export type UrlCheck = { ok: true; url: string } | { ok: false; message: string }

const INVALID_URL_MESSAGE = 'Adresse invalide. Utilisez une URL http ou https sans identifiant.'

export function parseHttpUrl(input: string): UrlCheck {
  const result = httpUrlSchema.safeParse(input.trim())
  if (!result.success) return { ok: false, message: INVALID_URL_MESSAGE }
  return { ok: true, url: result.data }
}
