// Replays the leaderboard's stored runs through this checkout's verifier (src/verify.ts on
// crimson-core/build/wasm/core.wasm), as the service verifies an upload, before a deploy
// that changes the core: a run the new build no longer accepts has to be retired
// (migrations/0005_retired.sql) with the reason, or the change rethought.
//
//   npm run reverify              every run not yet retired, from the production D1 and R2
//   npm run reverify -- <dir>     the .crd files in <dir>
//
// It reads production through wrangler and writes nothing there: the runs that fail
// are listed, with SQL to retire them for a migration. Each run that verifies also gets
// its ground baked (src/ground.ts) into .reverify/grounds/, from the built site's art
// (dist/ui), for `npm run grounds` to put in production once the build is deployed.
import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import { promisify } from "node:util";
import { downloadReplays } from "./reverify-cache.mjs";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const CORE = join(SERVICE, "../crimson-core/build/wasm/core.wasm");
const CACHE = join(SERVICE, ".reverify");
const GROUNDS = join(CACHE, "grounds");
const ART = join(SERVICE, "dist");
const execFileAsync = promisify(execFile);

const wrangler = (...args) =>
  execFileSync("npx", ["--no-install", "wrangler", ...args, "--remote", "--config", join(SERVICE, "wrangler.jsonc")], {
    cwd: SERVICE,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });

// The stored runs, as {id, file}: a directory's .crd files, or production's runs not yet retired,
// fetched once into .reverify/.
async function storedRuns(dir) {
  if (dir) return readdirSync(dir).filter((name) => name.endsWith(".crd")).map((name) => ({ id: name.slice(0, -4), file: join(dir, name) }));
  const [{ results }] = JSON.parse(wrangler("d1", "execute", "crimson-land", "--json", "--command", "SELECT id FROM runs WHERE retired IS NULL"));
  const start = performance.now();
  const { runs, downloaded } = await downloadReplays(results.map(({ id }) => id), CACHE, async (id, file) => {
    await execFileAsync("npx", ["--no-install", "wrangler", "r2", "object", "get", `crimson-land-replays/runs/${id}.crd`,
      "--file", file, "--remote", "--config", join(SERVICE, "wrangler.jsonc")], { cwd: SERVICE });
  });
  console.log(`Replays: ${downloaded} downloaded, ${runs.length - downloaded} cached in ${((performance.now() - start) / 1000).toFixed(2)}s`);
  return runs;
}

if (!existsSync(CORE)) throw Error(`build the core first: uv run python crimson-core/build.py --target wasm (${CORE})`);
if (!existsSync(join(ART, "ui"))) throw Error(`build the site first: npm run assets && npm run build (${ART})`);
const runs = await storedRuns(process.argv[2]);
// The service's own modules, with the worker's wasm imports as the compiled modules it binds.
const vite = await createServer({
  configFile: false,
  root: SERVICE,
  logLevel: "error",
  server: { middlewareMode: true, hmr: false },
  appType: "custom",
  plugins: [
    {
      name: "wasm-modules",
      enforce: "pre",
      load: (id) =>
        id.endsWith(".wasm")
          ? `import { readFileSync } from "node:fs"; export default new WebAssembly.Module(readFileSync(${JSON.stringify(id)}));`
          : null,
    },
  ],
});
const { decodeReplay, inflateReplay } = await vite.ssrLoadModule("/src/replay.ts");
const { encodeTransport } = await vite.ssrLoadModule("/src/transport.ts");
const { verifyRun } = await vite.ssrLoadModule("/src/verify.ts");
const { groundBake } = await vite.ssrLoadModule("/src/runs.ts");
const { encodeJpeg } = await vite.ssrLoadModule("/src/jpeg.ts");
// The worker's site files, as its ASSETS binding serves them.
const env = { ASSETS: { fetch: async (url) => new Response(readFileSync(join(ART, new URL(url).pathname))) } };
rmSync(GROUNDS, { recursive: true, force: true });
mkdirSync(GROUNDS, { recursive: true });

const started = performance.now();
const failed = [];
for (const { id, file } of runs) {
  const replay = decodeReplay(inflateReplay(new Uint8Array(readFileSync(file))));
  const start = performance.now();
  const ground = await groundBake(env, "https://crimson.land", replay);
  const verdict = await verifyRun(env, replay, encodeTransport(replay), (bakes) => ground.bake(bakes));
  if (!verdict.ok) failed.push({ id, reason: verdict.reason });
  else writeFileSync(join(GROUNDS, `${id}.jpg`), await encodeJpeg(ground.pixels()));
  console.log(`${id}  ${verdict.ok ? "ok" : verdict.reason}  ${((performance.now() - start) / 1000).toFixed(2)}s (${replay.ticks.length} ticks)`);
}
await vite.close();
console.log(`\n${runs.length - failed.length} of ${runs.length} runs verify in ${((performance.now() - started) / 1000).toFixed(2)}s; their grounds are in ${GROUNDS}.`);
if (failed.length) {
  console.log("To retire the rest (write each reason for players):");
  for (const { id, reason } of failed) console.log(`UPDATE runs SET retired = '${reason.replaceAll("'", "''")}' WHERE id = '${id}';`);
  process.exitCode = 1;
}
