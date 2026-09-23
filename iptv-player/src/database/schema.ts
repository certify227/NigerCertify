export interface TableContract {
  readonly name: string
  readonly columns: readonly string[]
  readonly indexes: readonly string[]
}

export const databaseSchema = {
  playlists: {
    name: 'playlists',
    columns: [
      'id',
      'name',
      'type',
      'location',
      'enabled',
      'added_at',
      'synced_at',
      'channel_count',
      'status',
    ],
    indexes: ['idx_playlists_enabled'],
  },
  channels: {
    name: 'channels',
    columns: [
      'id',
      'playlist_id',
      'name',
      'logo',
      'group_name',
      'stream_url',
      'tvg_id',
      'language',
      'country',
    ],
    indexes: ['idx_channels_playlist_group', 'idx_channels_name', 'idx_channels_tvg_id'],
  },
  favorites: {
    name: 'favorites',
    columns: ['channel_id', 'created_at'],
    indexes: ['idx_favorites_channel'],
  },
  history: {
    name: 'history',
    columns: ['id', 'channel_id', 'playlist_id', 'watched_at', 'duration_seconds'],
    indexes: ['idx_history_watched_at'],
  },
  settings: {
    name: 'settings',
    columns: ['key', 'value'],
    indexes: [],
  },
  epg_programs: {
    name: 'epg_programs',
    columns: ['id', 'tvg_id', 'title', 'starts_at', 'ends_at'],
    indexes: ['idx_epg_tvg_starts'],
  },
} as const satisfies Record<string, TableContract>

export const requiredTables = [
  'playlists',
  'channels',
  'favorites',
  'history',
  'settings',
  'epg_programs',
] as const
