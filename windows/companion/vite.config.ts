import { defineConfig } from "vite";

// The UI lives in ./ui; Tauri serves the built files from ./dist (tauri.conf.json frontendDist).
export default defineConfig({
  root: "ui",
  clearScreen: false,
  // Fold the preview switch to a constant so a normal build drops the mock (and its fake data)
  // from the bundle entirely; only `VITE_PREVIEW=1 npm run build` keeps it.
  define: { "import.meta.env.VITE_PREVIEW": JSON.stringify((globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env.VITE_PREVIEW ?? "") },
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
