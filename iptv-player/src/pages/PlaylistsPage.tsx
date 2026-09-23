import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'

const SOURCE_KINDS = [
  {
    title: 'URL M3U',
    detail: 'Adresse http ou https d’une playlist, sans identifiant dans le lien.',
  },
  {
    title: 'Fichier local',
    detail: 'Import d’un fichier playlist.m3u ou playlist.m3u8.',
  },
  {
    title: 'Xtream Codes',
    detail: 'URL du serveur, identifiant et mot de passe masqué, stocké hors de l’interface.',
  },
] as const

export function PlaylistsPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="Playlists"
        description="Plusieurs sources pourront coexister, avec un nom, un type, une date d'ajout et un état de synchronisation."
      />
      <ul className="grid gap-3 md:grid-cols-3">
        {SOURCE_KINDS.map((kind) => (
          <li key={kind.title} className="rounded-2xl border border-line bg-panel p-4">
            <h2 className="font-semibold">{kind.title}</h2>
            <p className="mt-2 text-sm leading-relaxed text-muted">{kind.detail}</p>
          </li>
        ))}
      </ul>
      <EmptyState
        title="Aucune playlist"
        description="L'ajout, la modification, la suppression et l'actualisation seront branchés sur cette page. Aucune liste n'est fournie avec l'application."
      />
    </div>
  )
}
