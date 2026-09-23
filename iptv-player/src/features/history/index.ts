export const historyFeature = {
  id: 'history',
  phase: 5,
  summary: 'Dernière chaîne, date et durée approximative de visionnage.',
} as const

export interface HistoryEntry {
  channelId: string
  playlistId: string
  watchedAt: string
  durationSeconds: number
}

export interface HistoryRepository {
  latest(): Promise<HistoryEntry | null>
  listRecent(limit: number): Promise<readonly HistoryEntry[]>
  record(entry: HistoryEntry): Promise<void>
  clear(): Promise<void>
}
