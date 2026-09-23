import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { PrimaryLink } from '@/components/PrimaryLink'

export function LiveTvPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="TV en direct"
        description="Les chaînes seront regroupées selon group-title, avec le logo, le nom, la catégorie et le statut du flux."
      />
      <div className="grid gap-4 lg:grid-cols-[16rem_minmax(0,1fr)]">
        <section aria-label="Catégories" className="rounded-2xl border border-line bg-panel p-4">
          <h2 className="text-sm font-semibold tracking-wide text-muted uppercase">Catégories</h2>
          <p className="mt-4 text-sm leading-relaxed text-muted">
            Aucune catégorie. Le nombre de chaînes apparaîtra ici après l'import d'une playlist.
          </p>
        </section>
        <EmptyState
          title="Aucune chaîne à afficher"
          description="Ajoutez une source autorisée pour voir les cartes de chaînes, le statut du flux et le bouton de lecture."
          action={<PrimaryLink to="/player">Ouvrir le lecteur</PrimaryLink>}
        />
      </div>
    </div>
  )
}
