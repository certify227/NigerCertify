import { PageHeader } from '@/components/PageHeader'
import { UPCOMING_SETTINGS } from '@/constants/settingsSections'
import { useUiStore, type ThemeName } from '@/stores/uiStore'
import { cn } from '@/utils/cn'

const THEMES: readonly { id: ThemeName; label: string }[] = [
  { id: 'dark', label: 'Sombre' },
  { id: 'light', label: 'Clair' },
]

export function SettingsPage() {
  const theme = useUiStore((state) => state.theme)
  const setTheme = useUiStore((state) => state.setTheme)

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="Paramètres"
        description="Le thème est déjà enregistré sur cet appareil. Les autres réglages seront activés avec le lecteur et la base locale."
      />
      <section className="rounded-2xl border border-line bg-panel p-5">
        <h2 className="text-lg font-semibold">Apparence</h2>
        <p className="mt-1 text-sm text-muted">Le mode sombre est le thème par défaut.</p>
        <div
          className="mt-4 inline-flex rounded-full bg-panel-2 p-1"
          role="group"
          aria-label="Thème"
        >
          {THEMES.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={theme === item.id}
              onClick={() => setTheme(item.id)}
              className={cn(
                'rounded-full px-4 py-2 text-sm font-medium text-muted',
                theme === item.id && 'bg-accent text-accent-ink',
              )}
            >
              {item.label}
            </button>
          ))}
        </div>
      </section>
      <div className="grid gap-4 md:grid-cols-2">
        {UPCOMING_SETTINGS.map((section) => (
          <section key={section.id} className="rounded-2xl border border-line bg-panel p-5">
            <h2 className="text-lg font-semibold">{section.title}</h2>
            <ul className="mt-3 space-y-2 text-sm text-muted">
              {section.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </div>
  )
}
