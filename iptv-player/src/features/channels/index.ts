import type { Channel } from '@/types/channel'

export const channelsFeature = {
  id: 'channels',
  phase: 3,
  summary: 'Catégories group-title, recherche et statut des flux.',
} as const

export interface ChannelQuery {
  playlistId?: string
  group?: string
  text?: string
}

export interface ChannelGroup {
  name: string
  count: number
}

export interface ChannelRepository {
  search(query: ChannelQuery): Promise<readonly Channel[]>
  groups(playlistId?: string): Promise<readonly ChannelGroup[]>
}
