import type { ReactNode } from 'react'
import { Link } from 'react-router'

export function PrimaryLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center justify-center rounded-full bg-accent px-4 py-2 text-sm font-semibold text-accent-ink transition-opacity hover:opacity-90"
    >
      {children}
    </Link>
  )
}
