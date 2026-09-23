import logoUrl from '@/assets/logo.svg'
import { APP_NAME } from '@/constants/app'

export function AppLogo({ labelled = false }: { labelled?: boolean }) {
  return (
    <img
      src={logoUrl}
      alt={labelled ? APP_NAME : ''}
      width={36}
      height={36}
      className="size-9 shrink-0 rounded-xl"
    />
  )
}
