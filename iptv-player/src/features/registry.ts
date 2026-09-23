import { channelsFeature } from './channels'
import { epgFeature } from './epg'
import { favoritesFeature } from './favorites'
import { historyFeature } from './history'
import { platformFeature } from './platform'

export { flutterMobileTargets } from './platform'
import { playerFeature } from './player'
import { playlistsFeature } from './playlists'
import { settingsFeature } from './settings'

export const features = [
  playlistsFeature,
  channelsFeature,
  playerFeature,
  favoritesFeature,
  historyFeature,
  epgFeature,
  settingsFeature,
  platformFeature,
] as const
