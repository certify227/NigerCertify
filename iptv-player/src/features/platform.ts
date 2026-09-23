export type ClientPlatform =
  | 'electron'
  | 'web'
  | 'android'
  | 'ios'
  | 'android-tv'
  | 'google-tv'
  | 'fire-tv'
  | 'smart-tv'

export interface PlatformAdapter {
  readonly id: ClientPlatform
}

export const electronPlatform = {
  id: 'electron',
} as const satisfies PlatformAdapter

export const flutterMobileTargets = ['android', 'ios'] as const satisfies readonly ClientPlatform[]

export const platformFeature = {
  id: 'platform',
  phase: 1,
  summary: 'Bureau Electron et client mobile Flutter pour Android et iOS.',
} as const
