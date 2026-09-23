export type ClientPlatform =
  'electron' | 'web' | 'android' | 'android-tv' | 'google-tv' | 'fire-tv' | 'smart-tv'

export interface PlatformAdapter {
  readonly id: ClientPlatform
}

export const electronPlatform = {
  id: 'electron',
} as const satisfies PlatformAdapter

export const platformFeature = {
  id: 'platform',
  phase: 1,
  summary: 'Adaptateur de bureau actuel. Les autres plateformes restent des contrats.',
} as const
