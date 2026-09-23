export const settingsFeature = {
  id: 'settings',
  phase: 8,
  summary: 'Préférences lecteur, réseau, guide TV et stockage.',
} as const

export interface PlayerSettings {
  autoplay: boolean
  preferredQuality: 'auto' | 'high' | 'medium' | 'low'
  bufferSeconds: number
  reconnect: boolean
}

export interface NetworkSettings {
  timeoutMs: number
  retries: number
  retryDelayMs: number
}

export interface EpgSettings {
  xmltvUrl: string | null
  syncIntervalMinutes: number
}

export interface SettingsRepository {
  getPlayer(): Promise<PlayerSettings>
  getNetwork(): Promise<NetworkSettings>
  getEpg(): Promise<EpgSettings>
}
