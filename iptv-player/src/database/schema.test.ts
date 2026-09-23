import { describe, expect, it } from 'vitest'
import { databaseSchema, requiredTables } from './schema'

describe('databaseSchema', () => {
  it('prévoit les tables demandées et des index de recherche', () => {
    expect(Object.keys(databaseSchema).sort()).toEqual([...requiredTables].sort())
    expect(databaseSchema.channels.indexes).toContain('idx_channels_name')
    expect(databaseSchema.channels.indexes).toContain('idx_channels_tvg_id')
    expect(databaseSchema.epg_programs.indexes).toContain('idx_epg_tvg_starts')
    expect(databaseSchema.favorites.columns).not.toContain('password')
    expect(databaseSchema.playlists.columns).not.toContain('password')
  })
})
