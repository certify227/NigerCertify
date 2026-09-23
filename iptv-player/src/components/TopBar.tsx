import { Menu, PanelLeft, Search } from 'lucide-react'
import { useLocation } from 'react-router'
import { titleForPath } from '@/constants/navigation'
import { useUiStore } from '@/stores/uiStore'

export function TopBar() {
  const { pathname } = useLocation()
  const title = titleForPath(pathname)
  const toggleSidebar = useUiStore((state) => state.toggleSidebar)
  const setMobileNavOpen = useUiStore((state) => state.setMobileNavOpen)
  const collapsed = useUiStore((state) => state.sidebarCollapsed)

  return (
    <header className="flex items-center gap-3 border-b border-line px-4 py-3 sm:px-6">
      <button
        type="button"
        className="grid size-10 place-items-center rounded-xl border border-line bg-panel text-ink lg:hidden"
        aria-label="Ouvrir le menu"
        onClick={() => setMobileNavOpen(true)}
      >
        <Menu size={18} />
      </button>
      <button
        type="button"
        className="hidden size-10 place-items-center rounded-xl border border-line bg-panel text-ink lg:grid"
        aria-label={collapsed ? 'Déplier le menu' : 'Réduire le menu'}
        aria-pressed={collapsed}
        onClick={toggleSidebar}
      >
        <PanelLeft size={18} />
      </button>
      <p className="min-w-0 flex-1 truncate text-sm font-medium text-muted sm:text-base">{title}</p>
      <label className="relative hidden w-full max-w-sm md:block">
        <Search
          aria-hidden="true"
          size={16}
          className="absolute top-1/2 left-3 -translate-y-1/2 text-muted"
        />
        <input
          type="search"
          disabled
          placeholder="Recherche disponible après une playlist"
          aria-label="Recherche globale"
          className="w-full rounded-full border border-line bg-panel py-2 pr-4 pl-9 text-sm text-muted"
        />
      </label>
    </header>
  )
}
