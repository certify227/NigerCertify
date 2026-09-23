import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { useUiStore } from '@/stores/uiStore'

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: query.includes('1024'),
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
})

afterEach(() => {
  document.documentElement.dataset.theme = 'dark'
  localStorage.clear()
  useUiStore.setState({ theme: 'dark', sidebarCollapsed: false, mobileNavOpen: false })
})
