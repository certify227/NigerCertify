import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { appRoutes } from '@/app/routes'
import { NAV_ITEMS } from '@/constants/navigation'

function renderAt(path: string) {
  const router = createMemoryRouter(appRoutes, { initialEntries: [path] })
  return render(<RouterProvider router={router} />)
}

describe('interface', () => {
  afterEach(() => {
    cleanup()
    delete window.aureon
  })

  it('affiche l accueil, la mention légale et le menu', () => {
    renderAt('/')
    expect(screen.getByRole('heading', { level: 1, name: 'Aureon' })).toBeInTheDocument()
    expect(screen.getByText(/ne fournit pas de liste IPTV/i)).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Navigation principale' })).toBeInTheDocument()
    for (const item of NAV_ITEMS) {
      expect(screen.getByRole('link', { name: item.label })).toBeInTheDocument()
    }
  })

  it('ouvre chaque écran depuis le menu', () => {
    renderAt('/')
    for (const item of NAV_ITEMS) {
      if (item.to === '/') continue
      fireEvent.click(screen.getByRole('link', { name: item.label }))
      expect(screen.getByRole('heading', { level: 1, name: item.label })).toBeInTheDocument()
    }
  })

  it('ouvre le cadre du lecteur sans lancer de flux', () => {
    renderAt('/player')
    expect(screen.getByText('Aucun flux en lecture')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Favori' })).toBeDisabled()
  })

  it('enregistre le thème clair', () => {
    renderAt('/settings')
    fireEvent.click(screen.getByRole('button', { name: 'Clair' }))
    expect(document.documentElement.dataset.theme).toBe('light')
    fireEvent.click(screen.getByRole('button', { name: 'Sombre' }))
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('réduit le menu avec Ctrl+B', () => {
    renderAt('/')
    const toggle = screen.getByRole('button', { name: 'Réduire le menu' })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
    fireEvent.keyDown(window, { key: 'b', ctrlKey: true })
    expect(screen.getByRole('button', { name: 'Déplier le menu' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
  })
})
