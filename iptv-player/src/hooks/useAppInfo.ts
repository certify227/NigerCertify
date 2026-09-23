import type { AppInfo } from '@shared/types'
import { useEffect, useState } from 'react'
import { logger } from '@/services/logger'

export type AppInfoStatus = 'browser' | 'loading' | 'ready' | 'error'

export function useAppInfo(): { status: AppInfoStatus; info: AppInfo | null } {
  const bridge = typeof window === 'undefined' ? undefined : window.aureon
  const [status, setStatus] = useState<AppInfoStatus>(bridge ? 'loading' : 'browser')
  const [info, setInfo] = useState<AppInfo | null>(null)

  useEffect(() => {
    if (!bridge) return
    let cancelled = false
    bridge.app
      .getInfo()
      .then((value) => {
        if (cancelled) return
        setInfo(value)
        setStatus('ready')
      })
      .catch((error: unknown) => {
        if (cancelled) return
        logger.warn("Lecture des informations de l'application impossible", error)
        setStatus('error')
      })
    return () => {
      cancelled = true
    }
  }, [bridge])

  return { status, info }
}
