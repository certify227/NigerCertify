import { createLogger, resolveLogLevel } from '@shared/logger'

export const logger = createLogger(
  'renderer',
  resolveLogLevel({
    explicit: import.meta.env.VITE_LOG_LEVEL,
    development: import.meta.env.DEV,
  }),
)
