import { PageHeader } from '@/components/PageHeader'

const FORMAT_SAMPLE = [
  { time: '18:00', title: 'Journal' },
  { time: '19:00', title: 'Sport' },
  { time: '20:00', title: 'Film' },
] as const

export function EpgPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <PageHeader
        title="Guide TV"
        description="Si un guide XMLTV est associé, le programme en cours et le suivant s'afficheront à partir du tvg-id. Sans guide, le lecteur continue de fonctionner."
      />
      <section
        aria-label="Aperçu du format"
        className="max-w-md rounded-2xl border border-line bg-panel p-5"
      >
        <h2 className="text-sm font-semibold tracking-wide text-muted uppercase">
          Aperçu du format
        </h2>
        <ol className="mt-4 space-y-3">
          {FORMAT_SAMPLE.map((item) => (
            <li key={item.time} className="flex items-baseline gap-4">
              <time className="w-14 font-medium text-accent">{item.time}</time>
              <span>{item.title}</span>
            </li>
          ))}
        </ol>
        <p className="mt-4 text-sm text-muted">
          Cet aperçu illustre la grille. Il ne correspond à aucune chaîne.
        </p>
      </section>
    </div>
  )
}
