import { app, ipcMain } from 'electron'
import { IpcChannel } from '@shared/ipc'
import type { AppInfo } from '@shared/types'

export function registerIpc(): void {
  ipcMain.handle(IpcChannel.appGetInfo, (): AppInfo => {
    return {
      name: app.getName(),
      version: app.getVersion(),
      platform: process.platform,
      runtime: 'electron',
    }
  })
}
