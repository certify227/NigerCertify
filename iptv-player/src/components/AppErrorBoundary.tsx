import { Component, type ErrorInfo, type ReactNode } from 'react'
import { APP_NAME } from '@/constants/app'
import { logger } from '@/services/logger'

interface AppErrorBoundaryState {
  failed: boolean
}

export class AppErrorBoundary extends Component<{ children: ReactNode }, AppErrorBoundaryState> {
  override state: AppErrorBoundaryState = { failed: false }

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true }
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    logger.error("Erreur d'interface", {
      message: error.message,
      componentStack: info.componentStack,
    })
  }

  override render(): ReactNode {
    if (!this.state.failed) return this.props.children
    return (
      <div className="grid min-h-dvh place-items-center bg-canvas px-6 text-center text-ink">
        <div className="max-w-md">
          <h1 className="text-2xl font-semibold">Une erreur inattendue est survenue</h1>
          <p className="mt-3 text-muted">
            Relancez {APP_NAME}. Le détail technique reste dans les journaux.
          </p>
        </div>
      </div>
    )
  }
}
