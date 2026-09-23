export const favoritesFeature = {
  id: 'favorites',
  phase: 5,
  summary: 'Favoris conservés localement entre les redémarrages.',
} as const

export interface FavoriteRepository {
  listIds(): Promise<readonly string[]>
  add(channelId: string): Promise<void>
  remove(channelId: string): Promise<void>
}
