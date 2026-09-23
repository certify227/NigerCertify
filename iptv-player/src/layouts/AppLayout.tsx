import { useEffect } from 'react'
import { Outlet, useLocation } from 'react-router'
import { Sidebar } from '@/components/Sidebar'
import { TopBar } from '@/components/TopBar'
import { APP_NAME } from '@/constants/app'
import { titleForPath } from '@/constants/navigation'
import { useShellKeyboard } from '@/hooks/useShellKeyboard'
import { useUiStore } from '@/stores/uiStore'

export function AppLayout() {
  const theme = useUiStore((state) => state.theme)
  const { pathname } = useLocation()
  useShellKeyboard()

  useEffect(() => {
    void useUiStore.persist.rehydrate()
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  useEffect(() => {
    document.title = `${titleForPath(pathname)} · ${APP_NAME}`
  }, [pathname])

  return (
    <div className="flex h-dvh overflow-hidden text-ink">
      <a
        href="#contenu"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:rounded-lg focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-ink"
      >
        Aller au contenu
      </a>
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main id="contenu" className="min-h-0 flex-1 overflow-y-auto px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
