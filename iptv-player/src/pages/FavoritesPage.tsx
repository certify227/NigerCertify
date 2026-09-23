import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'

export function FavoritesPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="Favoris"
        description="Les chaînes épinglées resteront disponibles après le redémarrage de l'application."
      />
      <EmptyState
        title="Aucun favori"
        description="L'étoile d'une carte de chaîne permettra de l'ajouter ou de la retirer. Rien n'est enregistré tant qu'aucune chaîne n'est importée."
      />
    </div>
  )
}
