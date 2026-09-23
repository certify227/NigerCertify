import { NavLink } from 'react-router'
import { APP_NAME } from '@/constants/app'
import { NAV_ITEMS } from '@/constants/navigation'
import { useAppInfo } from '@/hooks/useAppInfo'
import { useUiStore } from '@/stores/uiStore'
import { cn } from '@/utils/cn'
import { AppLogo } from './AppLogo'

export function Sidebar() {
  const collapsed = useUiStore((state) => state.sidebarCollapsed)
  const mobileNavOpen = useUiStore((state) => state.mobileNavOpen)
  const setMobileNavOpen = useUiStore((state) => state.setMobileNavOpen)
  const { status, info } = useAppInfo()

  const runtimeLabel =
    status === 'ready' && info
      ? `${info.version} · ${info.platform}`
      : status === 'loading'
        ? 'Connexion…'
        : status === 'error'
          ? 'Informations indisponibles'
          : 'Aperçu navigateur'

  return (
    <>
      <button
        type="button"
        className={cn(
          'fixed inset-0 z-30 bg-black/50 lg:hidden',
          mobileNavOpen ? 'block' : 'hidden',
        )}
        aria-label="Fermer le menu"
        onClick={() => setMobileNavOpen(false)}
      />
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-line bg-panel transition-transform lg:static lg:translate-x-0',
          mobileNavOpen ? 'translate-x-0' : '-translate-x-full',
          collapsed && 'lg:w-20',
        )}
      >
        <div
          className={cn(
            'flex items-center gap-3 px-4 py-5',
            collapsed && 'lg:justify-center lg:px-2',
          )}
        >
          <AppLogo labelled={collapsed} />
          <div className={cn(collapsed && 'lg:hidden')}>
            <p className="text-base font-semibold tracking-tight">{APP_NAME}</p>
            <p className="text-xs text-muted">Sources autorisées</p>
          </div>
        </div>
        <nav aria-label="Navigation principale" className="flex-1 space-y-1 px-3">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon
            return (
              <NavLink
                key={item.id}
                to={item.to}
                end={item.to === '/'}
                title={item.label}
                onClick={() => setMobileNavOpen(false)}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-muted hover:bg-panel-2 hover:text-ink',
                    collapsed && 'lg:justify-center lg:px-2',
                    isActive && 'bg-panel-2 text-ink shadow-[inset_3px_0_0_0_var(--color-accent)]',
                  )
                }
              >
                <Icon aria-hidden="true" size={18} />
                <span className={cn(collapsed && 'lg:hidden')}>{item.label}</span>
              </NavLink>
            )
          })}
        </nav>
        <p className={cn('px-4 py-4 text-xs text-muted', collapsed && 'lg:px-2 lg:text-center')}>
          {runtimeLabel}
        </p>
      </aside>
    </>
  )
}
