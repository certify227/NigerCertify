export type PlaylistType = 'm3u-url' | 'm3u-file' | 'xtream'

export type PlaylistStatus = 'idle' | 'syncing' | 'ready' | 'error'

export interface Playlist {
  id: string
  name: string
  type: PlaylistType
  enabled: boolean
  addedAt: string
  syncedAt: string | null
  channelCount: number
  status: PlaylistStatus
}
