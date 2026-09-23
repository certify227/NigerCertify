export const playerFeature = {
  id: 'player',
  phase: 4,
  summary: 'Lecture HLS avec reprise, erreurs lisibles et raccourcis.',
} as const

export type PlaybackState = 'idle' | 'loading' | 'playing' | 'paused' | 'error'

export type PlaybackErrorCode =
  | 'unavailable'
  | 'timeout'
  | 'http'
  | 'offline'
  | 'invalid-url'
  | 'unsupported'
  | 'interrupted'
  | 'expired-playlist'

export interface PlaybackError {
  code: PlaybackErrorCode
  userMessage: string
}

export interface PlaybackEngine {
  load(streamUrl: string): Promise<void>
  play(): Promise<void>
  pause(): void
  setMuted(muted: boolean): void
  setVolume(volume: number): void
  destroy(): void
}
