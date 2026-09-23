import { app, BrowserWindow } from 'electron'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createLogger, resolveLogLevel } from '@shared/logger'
import { registerIpc } from './ipc'
import { installContentSecurityPolicy, installNavigationGuards } from './security'

const currentDir = fileURLToPath(new URL('.', import.meta.url))
const logger = createLogger(
  'main',
  resolveLogLevel({
    explicit: process.env.AUREON_LOG_LEVEL,
    development: Boolean(process.env.ELECTRON_RENDERER_URL),
  }),
)

function createWindow(): BrowserWindow {
  const window = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    show: false,
    backgroundColor: '#0c0e12',
    autoHideMenuBar: true,
    title: 'Aureon',
    webPreferences: {
      preload: join(currentDir, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  })

  window.on('ready-to-show', () => {
    window.show()
  })

  if (process.env.AUREON_OPEN_DEVTOOLS === '1') {
    window.webContents.openDevTools({ mode: 'detach' })
  }

  const devUrl = process.env.ELECTRON_RENDERER_URL
  if (devUrl) {
    void window.loadURL(devUrl)
  } else {
    void window.loadFile(join(currentDir, '../renderer/index.html'))
  }

  return window
}

const hasLock = app.requestSingleInstanceLock()
if (!hasLock) {
  app.quit()
} else {
  app.on('second-instance', () => {
    const window = BrowserWindow.getAllWindows()[0]
    if (!window) return
    if (window.isMinimized()) window.restore()
    window.focus()
  })

  app
    .whenReady()
    .then(() => {
      installContentSecurityPolicy()
      installNavigationGuards(logger)
      registerIpc()
      createWindow()
      logger.info('Fenêtre principale prête')

      app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow()
      })
    })
    .catch((error: unknown) => {
      logger.error('Échec du démarrage', error)
      app.quit()
    })

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit()
  })
}
