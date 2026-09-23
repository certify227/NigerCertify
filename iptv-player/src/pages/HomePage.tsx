import { PrimaryLink } from '@/components/PrimaryLink'
import { PageHeader } from '@/components/PageHeader'
import { StatusCard } from '@/components/StatusCard'
import { APP_NAME, APP_TAGLINE } from '@/constants/app'
import { useAppInfo } from '@/hooks/useAppInfo'

export function HomePage() {
  const { status, info } = useAppInfo()
  const runtime =
    status === 'ready' && info
      ? `${APP_NAME} ${info.version} sur ${info.platform}`
      : status === 'loading'
        ? 'Connexion au processus de bureau…'
        : status === 'error'
          ? "Les informations de l'application sont indisponibles."
          : 'Cette fenêtre est un aperçu navigateur. Le bureau Electron expose la même interface.'

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8">
      <PageHeader eyebrow="Lecteur IPTV" title={APP_NAME} description={APP_TAGLINE} />
      <section aria-label="État de la bibliothèque" className="grid gap-4 md:grid-cols-3">
        <StatusCard label="Playlists" value="0" detail="Aucune source enregistrée" />
        <StatusCard label="Favoris" value="0" detail="Aucune chaîne épinglée" />
        <StatusCard label="Reprise" value="—" detail="Aucune lecture récente" />
      </section>
      <section className="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <div className="rounded-2xl border border-line bg-panel p-6">
          <h2 className="text-lg font-semibold">Aucune chaîne intégrée</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">
            {APP_NAME} ne fournit pas de liste IPTV. Vous ajouterez ensuite vos propres playlists
            M3U ou un accès Xtream que vous êtes autorisé à utiliser.
          </p>
          <div className="mt-5">
            <PrimaryLink to="/playlists">Ouvrir les playlists</PrimaryLink>
          </div>
        </div>
        <div className="rounded-2xl border border-line bg-panel p-6">
          <h2 className="text-lg font-semibold">Environnement</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">{runtime}</p>
          <p className="mt-4 text-sm text-muted">
            Raccourci : Ctrl+B ou ⌘B réduit le menu latéral.
          </p>
        </div>
      </section>
    </div>
  )
}
