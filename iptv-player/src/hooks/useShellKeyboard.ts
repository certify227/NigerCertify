import { useEffect } from 'react'
import { useMediaQuery } from '@/hooks/useMediaQuery'
import { useUiStore } from '@/stores/uiStore'

function isTypingTarget(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLElement &&
    Boolean(target.closest('input, textarea, [contenteditable="true"]'))
  )
}

export function useShellKeyboard(): void {
  const desktop = useMediaQuery('(min-width: 1024px)')
  const toggleSidebar = useUiStore((state) => state.toggleSidebar)
  const mobileNavOpen = useUiStore((state) => state.mobileNavOpen)
  const setMobileNavOpen = useUiStore((state) => state.setMobileNavOpen)

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape' && mobileNavOpen) {
        setMobileNavOpen(false)
        return
      }
      if (event.key.toLowerCase() !== 'b' || event.altKey || !(event.metaKey || event.ctrlKey))
        return
      if (isTypingTarget(event.target)) return
      event.preventDefault()
      if (desktop) toggleSidebar()
      else setMobileNavOpen(!mobileNavOpen)
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [desktop, mobileNavOpen, setMobileNavOpen, toggleSidebar])
}
