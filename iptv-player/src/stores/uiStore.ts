import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type ThemeName = 'dark' | 'light'

interface UiState {
  theme: ThemeName
  sidebarCollapsed: boolean
  mobileNavOpen: boolean
  setTheme: (theme: ThemeName) => void
  toggleSidebar: () => void
  setMobileNavOpen: (open: boolean) => void
}

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      theme: 'dark',
      sidebarCollapsed: false,
      mobileNavOpen: false,
      setTheme: (theme) => set({ theme }),
      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setMobileNavOpen: (mobileNavOpen) => set({ mobileNavOpen }),
    }),
    {
      name: 'aureon-ui',
      skipHydration: true,
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
    },
  ),
)
