import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'electron-vite'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('.', import.meta.url))

const alias = {
  '@': resolve(root, 'src'),
  '@shared': resolve(root, 'shared'),
}

export default defineConfig({
  main: {
    resolve: { alias },
    build: {
      rollupOptions: {
        input: resolve(root, 'electron/main/index.ts'),
      },
    },
  },
  preload: {
    resolve: { alias },
    build: {
      rollupOptions: {
        input: resolve(root, 'electron/preload/index.ts'),
        output: {
          format: 'cjs',
          entryFileNames: 'index.js',
        },
      },
    },
  },
  renderer: {
    root,
    resolve: { alias },
    plugins: [react(), tailwindcss()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
    },
    build: {
      minify: true,
      rollupOptions: {
        input: resolve(root, 'index.html'),
      },
    },
  },
})
