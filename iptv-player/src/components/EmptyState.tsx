import type { ReactNode } from 'react'

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="rounded-2xl border border-dashed border-line bg-panel/70 px-6 py-10 text-center">
      <h2 className="text-lg font-semibold">{title}</h2>
      <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-muted">{description}</p>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  )
}
