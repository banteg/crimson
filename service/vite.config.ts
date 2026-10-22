import { readdirSync, readFileSync } from "node:fs";
import { marked } from "marked";
import { defineConfig, type Plugin } from "vite";
import solid from "vite-plugin-solid";

// News posts: news/YYYY-MM-DD-slug.md, each opening with its "# Title". The site imports them as "virtual:news",
// rendered to HTML at build time, newest first.
function news(): Plugin {
  const id = "virtual:news";
  const dir = new URL("news/", import.meta.url);
  return {
    name: "news",
    resolveId: (source) => (source === id ? `\0${id}` : null),
    load(resolved) {
      if (resolved !== `\0${id}`) return null;
      const files = readdirSync(dir).filter((file) => file.endsWith(".md")).sort().reverse();
      const posts = files.map((file) => {
        const path = new URL(file, dir);
        this.addWatchFile(path.pathname);
        const name = /^(\d{4}-\d{2}-\d{2})-([a-z0-9-]+)\.md$/.exec(file);
        const text = /^# (.+)\n([\s\S]*)$/.exec(readFileSync(path, "utf8"));
        if (!name || !text) throw new Error(`news/${file}: expected YYYY-MM-DD-slug.md opening with "# Title"`);
        return { date: name[1], slug: name[2], title: text[1], html: marked.parse(text[2]!, { async: false }) };
      });
      return `export default ${JSON.stringify(posts)};`;
    },
  };
}

// The site: web/ builds into dist/, which the Worker serves (wrangler.jsonc "assets"); public/ holds the game's art
// that scripts/assets.py exports.
export default defineConfig({
  root: "web",
  publicDir: "../public",
  plugins: [solid(), news()],
  build: { outDir: "../dist", emptyOutDir: true },
  server: { proxy: { "/api": "http://localhost:8787", "/login": "http://localhost:8787", "/auth": "http://localhost:8787", "/runs": "http://localhost:8787" } },
});
