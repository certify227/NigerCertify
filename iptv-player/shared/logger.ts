import { z } from 'zod'
import { redact, redactText } from './redact'
import type { LogLevel } from './types'

const WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
}

export const logLevelSchema = z.enum(['debug', 'info', 'warn', 'error'])

export function resolveLogLevel(options: {
  explicit: string | undefined
  development: boolean
}): LogLevel {
  const parsed = logLevelSchema.safeParse(options.explicit)
  if (parsed.success) return parsed.data
  return options.development ? 'debug' : 'info'
}

export interface Logger {
  debug: (message: string, details?: unknown) => void
  info: (message: string, details?: unknown) => void
  warn: (message: string, details?: unknown) => void
  error: (message: string, details?: unknown) => void
}

function formatDetails(details: unknown, verboseErrors: boolean): string {
  if (details instanceof Error) {
    const text = verboseErrors ? (details.stack ?? details.message) : details.message
    return ` ${redactText(text)}`
  }
  try {
    return ` ${JSON.stringify(redact(details))}`
  } catch {
    return ' [unserializable]'
  }
}

export function createLogger(
  scope: string,
  level: LogLevel,
  verboseErrors = level === 'debug',
): Logger {
  const write = (current: LogLevel, message: string, details?: unknown): void => {
    if (WEIGHT[current] < WEIGHT[level]) return
    const suffix = details === undefined ? '' : formatDetails(details, verboseErrors)
    const line = `[${current.toUpperCase()}] [${scope}] ${redactText(message)}${suffix}`
    if (current === 'error') console.error(line)
    else if (current === 'warn') console.warn(line)
    else console.info(line)
  }

  return {
    debug: (message, details) => write('debug', message, details),
    info: (message, details) => write('info', message, details),
    warn: (message, details) => write('warn', message, details),
    error: (message, details) => write('error', message, details),
  }
}
