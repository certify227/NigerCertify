import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'

export function HistoryPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="Historique"
        description="La dernière chaîne, l'heure, la playlist et une durée approximative de visionnage seront listées ici."
      />
      <EmptyState
        title="Aucune reprise"
        description="Le bouton Reprendre apparaîtra lorsqu'une lecture aura été enregistrée."
      />
    </div>
  )
}
