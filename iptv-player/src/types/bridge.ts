import type { AureonBridge } from '@shared/types'

export type { AureonBridge }

declare global {
  interface Window {
    aureon?: AureonBridge
  }
}
