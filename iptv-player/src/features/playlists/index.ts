import type { Playlist } from '@/types/playlist'

export const playlistsFeature = {
  id: 'playlists',
  phase: 3,
  summary: 'Ajout, synchronisation et activation de plusieurs playlists M3U ou Xtream.',
} as const

export interface SecretStore {
  write(account: string, secret: string): Promise<void>
  read(account: string): Promise<string | null>
  delete(account: string): Promise<void>
}

export interface CreateXtreamPlaylistInput {
  name: string
  serverUrl: string
  username: string
  password: string
}

export interface PlaylistRepository {
  list(): Promise<readonly Playlist[]>
  setEnabled(id: string, enabled: boolean): Promise<void>
  remove(id: string): Promise<void>
  refresh(id: string): Promise<void>
  createFromUrl(input: { name: string; url: string }): Promise<Playlist>
  createFromFile(input: { name: string; fileName: string; contents: string }): Promise<Playlist>
  createFromXtream(input: CreateXtreamPlaylistInput, secrets: SecretStore): Promise<Playlist>
}
