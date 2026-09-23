import '@fontsource-variable/outfit'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router'
import { appRoutes } from '@/app/routes'
import { AppErrorBoundary } from '@/components/AppErrorBoundary'
import '@/index.css'

const root = document.getElementById('root')
if (!root) throw new Error('Point de montage introuvable.')

const router = createBrowserRouter(appRoutes)

createRoot(root).render(
  <StrictMode>
    <AppErrorBoundary>
      <RouterProvider router={router} />
    </AppErrorBoundary>
  </StrictMode>,
)
