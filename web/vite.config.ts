import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig(({ command }) => ({
  plugins: [react()],
  // Deployed to a GitHub Pages *project* page (repo subpath, not a user/org
  // root page), so production asset URLs need the repo name as a base -
  // only for `build`, so `npm run dev` still serves from / locally.
  base: command === 'build' ? '/THEncrypterX/' : '/',
}))
