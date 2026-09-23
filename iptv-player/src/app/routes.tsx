import { AppLayout } from '@/layouts/AppLayout'
import { EpgPage } from '@/pages/EpgPage'
import { FavoritesPage } from '@/pages/FavoritesPage'
import { HistoryPage } from '@/pages/HistoryPage'
import { HomePage } from '@/pages/HomePage'
import { LiveTvPage } from '@/pages/LiveTvPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { PlayerPage } from '@/pages/PlayerPage'
import { PlaylistsPage } from '@/pages/PlaylistsPage'
import { SettingsPage } from '@/pages/SettingsPage'
import type { RouteObject } from 'react-router'

export const appRoutes: RouteObject[] = [
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'live', element: <LiveTvPage /> },
      { path: 'favorites', element: <FavoritesPage /> },
      { path: 'history', element: <HistoryPage /> },
      { path: 'playlists', element: <PlaylistsPage /> },
      { path: 'epg', element: <EpgPage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: 'player', element: <PlayerPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]
