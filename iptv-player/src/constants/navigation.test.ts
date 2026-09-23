import { describe, expect, it } from 'vitest'
import { NAV_ITEMS, titleForPath } from './navigation'

describe('navigation', () => {
  it('expose des routes uniques pour chaque écran principal', () => {
    const routes = NAV_ITEMS.map((item) => item.to)
    expect(new Set(routes).size).toBe(routes.length)
    expect(routes).toEqual([
      '/',
      '/live',
      '/favorites',
      '/history',
      '/playlists',
      '/epg',
      '/settings',
    ])
  })

  it('nomme le lecteur et les pages inconnues', () => {
    expect(titleForPath('/')).toBe('Accueil')
    expect(titleForPath('/live')).toBe('TV en direct')
    expect(titleForPath('/player')).toBe('Lecteur')
    expect(titleForPath('/ailleurs')).toBe('Aureon')
  })
})
