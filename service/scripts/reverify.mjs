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
// Runs verify on one worker thread per CPU (reverify-worker.mjs).
import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { availableParallelism } from "node:os";
import { promisify } from "node:util";
import { downloadReplays } from "./reverify-cache.mjs";
import { verifyRuns } from "./reverify-pool.mjs";

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
rmSync(GROUNDS, { recursive: true, force: true });
mkdirSync(GROUNDS, { recursive: true });

const started = performance.now();
const results = await verifyRuns(runs, {
  jobs: availableParallelism(),
  workerData: { service: SERVICE, art: ART, grounds: GROUNDS },
  onResult: ({ id, ok, reason, seconds, ticks }) =>
    console.log(`${id}  ${ok ? "ok" : reason}  ${seconds.toFixed(2)}s (${ticks} ticks)`),
});
const failed = results.filter(({ ok }) => !ok);
console.log(`\n${runs.length - failed.length} of ${runs.length} runs verify in ${((performance.now() - started) / 1000).toFixed(2)}s; their grounds are in ${GROUNDS}.`);
if (failed.length) {
  console.log("To retire the rest (write each reason for players):");
  for (const { id, reason } of failed) console.log(`UPDATE runs SET retired = '${reason.replaceAll("'", "''")}' WHERE id = '${id}';`);
  process.exitCode = 1;
}
