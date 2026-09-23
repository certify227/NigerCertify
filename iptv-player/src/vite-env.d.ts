/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_APP_NAME?: string
  readonly VITE_LOG_LEVEL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
