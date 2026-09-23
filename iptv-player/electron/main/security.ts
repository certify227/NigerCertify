import { app, session, type Session } from 'electron'
import type { Logger } from '@shared/logger'
import { redactText } from '@shared/redact'

const PRODUCTION_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: https:",
  "media-src 'self' blob: https: http:",
  "connect-src 'self'",
  "font-src 'self' data:",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'none'",
].join('; ')

function isDevRenderer(url: string): boolean {
  const devUrl = process.env.ELECTRON_RENDERER_URL
  return typeof devUrl === 'string' && devUrl.length > 0 && url.startsWith(devUrl)
}

export function isAllowedAppNavigation(url: string): boolean {
  return url.startsWith('file://') || isDevRenderer(url)
}

function developmentCsp(rendererUrl: string): string {
  const host = new URL(rendererUrl).host
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    `connect-src 'self' ws://${host}`,
    "font-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
  ].join('; ')
}

export function installContentSecurityPolicy(target: Session = session.defaultSession): void {
  const rendererUrl = process.env.ELECTRON_RENDERER_URL
  const policy = rendererUrl ? developmentCsp(rendererUrl) : PRODUCTION_CSP

  target.webRequest.onHeadersReceived((details, callback) => {
    if (details.resourceType !== 'mainFrame') {
      callback({ responseHeaders: details.responseHeaders })
      return
    }
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [policy],
      },
    })
  })
}

export function installNavigationGuards(logger: Logger): void {
  app.on('web-contents-created', (_event, contents) => {
    contents.on('will-navigate', (event, url) => {
      if (isAllowedAppNavigation(url)) return
      event.preventDefault()
      logger.warn('Navigation externe bloquée', { url: redactText(url) })
    })

    contents.setWindowOpenHandler(({ url }) => {
      logger.warn('Ouverture de fenêtre bloquée', { url: redactText(url) })
      return { action: 'deny' }
    })

    contents.on('will-attach-webview', (event) => {
      event.preventDefault()
      logger.warn('Webview refusée')
    })
  })

  session.defaultSession.setPermissionRequestHandler((_contents, permission, callback) => {
    callback(permission === 'fullscreen')
  })
}
