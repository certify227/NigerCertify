import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { PrimaryLink } from '@/components/PrimaryLink'

export function NotFoundPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="Page introuvable"
        description="Cette adresse ne correspond à aucun écran d'Aureon."
      />
      <EmptyState
        title="Retour à l'accueil"
        description="Le menu latéral reste disponible."
        action={<PrimaryLink to="/">Accueil</PrimaryLink>}
      />
    </div>
  )
}
