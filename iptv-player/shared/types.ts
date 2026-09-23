export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface AppInfo {
  name: string
  version: string
  platform: string
  runtime: 'electron'
}

export interface AureonBridge {
  app: {
    getInfo: () => Promise<AppInfo>
  }
}
