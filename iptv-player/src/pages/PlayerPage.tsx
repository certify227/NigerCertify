import { Heart, Play } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'

const SIDE_PANELS = ['Chaînes similaires', 'Chaînes récentes', 'Favoris'] as const

export function PlayerPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="Lecteur"
        description="Le cadre HLS, les contrôles et les messages d'erreur viendront se placer ici. Aucun flux n'est lancé."
      />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <section aria-label="Zone de lecture">
          <div className="relative flex aspect-video items-center justify-center overflow-hidden rounded-2xl border border-line bg-black text-center">
            <div>
              <Play aria-hidden="true" className="mx-auto text-accent" />
              <p className="mt-3 text-sm text-white/80">Aucun flux en lecture</p>
            </div>
          </div>
          <div className="mt-4 flex items-start justify-between gap-4">
            <div>
              <h2 className="text-xl font-semibold">Aucune chaîne</h2>
              <p className="mt-1 text-sm text-muted">
                Sélectionnez une chaîne lorsque une playlist sera disponible.
              </p>
            </div>
            <button
              type="button"
              disabled
              className="inline-flex items-center gap-2 rounded-full border border-line px-3 py-2 text-sm text-muted"
            >
              <Heart aria-hidden="true" size={16} />
              Favori
            </button>
          </div>
        </section>
        <aside className="space-y-3">
          {SIDE_PANELS.map((title) => (
            <section key={title} className="rounded-2xl border border-line bg-panel p-4">
              <h2 className="text-sm font-semibold">{title}</h2>
              <p className="mt-2 text-sm text-muted">Aucune entrée.</p>
            </section>
          ))}
        </aside>
      </div>
    </div>
  )
}
