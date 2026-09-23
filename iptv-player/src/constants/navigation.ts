import {
  CalendarDays,
  Heart,
  History,
  House,
  ListVideo,
  Settings,
  Tv,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  id: string
  label: string
  to: string
  icon: LucideIcon
  description: string
}

export const NAV_ITEMS: readonly NavItem[] = [
  {
    id: 'home',
    label: 'Accueil',
    to: '/',
    icon: House,
    description: "Vue d'ensemble de la bibliothèque.",
  },
  {
    id: 'live',
    label: 'TV en direct',
    to: '/live',
    icon: Tv,
    description: 'Chaînes regroupées par catégorie.',
  },
  {
    id: 'favorites',
    label: 'Favoris',
    to: '/favorites',
    icon: Heart,
    description: 'Chaînes épinglées sur cet appareil.',
  },
  {
    id: 'history',
    label: 'Historique',
    to: '/history',
    icon: History,
    description: 'Reprises récentes.',
  },
  {
    id: 'playlists',
    label: 'Playlists',
    to: '/playlists',
    icon: ListVideo,
    description: 'Sources M3U et Xtream fournies par vous.',
  },
  {
    id: 'epg',
    label: 'Guide TV',
    to: '/epg',
    icon: CalendarDays,
    description: 'Programme actuel lorsque un guide XMLTV est disponible.',
  },
  {
    id: 'settings',
    label: 'Paramètres',
    to: '/settings',
    icon: Settings,
    description: 'Apparence, lecteur, réseau et stockage.',
  },
]

const APP_FALLBACK_TITLE = 'Aureon'

export function titleForPath(pathname: string): string {
  if (pathname === '/player' || pathname.startsWith('/player/')) return 'Lecteur'
  const match = NAV_ITEMS.find((item) =>
    item.to === '/' ? pathname === '/' : pathname === item.to || pathname.startsWith(`${item.to}/`),
  )
  return match?.label ?? APP_FALLBACK_TITLE
}
