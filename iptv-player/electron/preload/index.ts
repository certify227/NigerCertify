import { contextBridge, ipcRenderer } from 'electron'
import { IpcChannel } from '@shared/ipc'
import type { AppInfo, AureonBridge } from '@shared/types'

const bridge: AureonBridge = {
  app: {
    getInfo: (): Promise<AppInfo> => ipcRenderer.invoke(IpcChannel.appGetInfo) as Promise<AppInfo>,
  },
}

if (!process.contextIsolated) {
  throw new Error('contextIsolation est obligatoire.')
}

contextBridge.exposeInMainWorld('aureon', bridge)
