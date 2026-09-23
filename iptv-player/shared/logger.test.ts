import { afterEach, describe, expect, it, vi } from 'vitest'
import { createLogger, resolveLogLevel } from './logger'

describe('logger', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('n écrit pas les secrets et ignore le niveau debug hors mode verbeux', () => {
    const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => undefined)
    const logger = createLogger('test', 'info')

    logger.debug('détail', { password: 'super-secret' })
    logger.info('playlist chargée', {
      password: 'super-secret',
      stream: 'https://alice:s3cret@example.com/a.m3u8',
    })

    expect(debug).not.toHaveBeenCalled()
    const output = info.mock.calls.map((call) => call.join(' ')).join('\n')
    expect(output).toContain('[INFO] [test] playlist chargée')
    expect(output).not.toContain('super-secret')
    expect(output).not.toContain('s3cret')
    expect(output).toContain('[redacted]')
  })

  it('active debug en développement quand aucun niveau n est fourni', () => {
    expect(resolveLogLevel({ explicit: undefined, development: true })).toBe('debug')
    expect(resolveLogLevel({ explicit: 'warn', development: true })).toBe('warn')
    expect(resolveLogLevel({ explicit: 'nope', development: false })).toBe('info')
  })
})
