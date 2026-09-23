export const epgFeature = {
  id: 'epg',
  phase: 6,
  summary: 'Import XMLTV, programme en cours et grille TV.',
} as const

export interface EpgProgram {
  tvgId: string
  title: string
  startsAt: string
  endsAt: string
}

export interface EpgRepository {
  importFromUrl(url: string): Promise<void>
  current(tvgId: string, at: Date): Promise<EpgProgram | null>
  upcoming(tvgId: string, at: Date, limit: number): Promise<readonly EpgProgram[]>
}
