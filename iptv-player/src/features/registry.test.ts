import { describe, expect, it } from 'vitest'
import { features, flutterMobileTargets } from './registry'

describe('features', () => {
  it('déclare des modules distincts, prêts à être branchés plus tard', () => {
    const ids = features.map((feature) => feature.id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(features.every((feature) => feature.phase >= 1 && feature.summary.length > 0)).toBe(true)
    expect(flutterMobileTargets).toEqual(['android', 'ios'])
  })
})
