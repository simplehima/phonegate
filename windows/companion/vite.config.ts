import { defineConfig } from "vite";

// The UI lives in ./ui; Tauri serves the built files from ./dist (tauri.conf.json frontendDist).
export default defineConfig({
  root: "ui",
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  preview: { port: 4173, strictPort: true },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2022",
    // Inline nothing: the CSP has no 'unsafe-inline' and no data: fonts.
    assetsInlineLimit: 0,
  },
});
