import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// The site: web/ builds into dist/, which the Worker serves (wrangler.jsonc "assets"); public/ holds the game's art
// that scripts/assets.py exports.
export default defineConfig({
  root: "web",
  publicDir: "../public",
  plugins: [solid()],
  build: { outDir: "../dist", emptyOutDir: true },
  server: { proxy: { "/api": "http://localhost:8787", "/login": "http://localhost:8787", "/auth": "http://localhost:8787", "/runs": "http://localhost:8787" } },
});
