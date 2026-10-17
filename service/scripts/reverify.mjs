// Replays stored runs through this checkout's verifier (src/verify.ts on crimson-core/build/wasm/core.wasm), as the
// service verifies an upload, so a change that breaks a run is caught before it ships: a run the new build no longer
// accepts has to be retired (migrations/0005_retired.sql) with the reason, or the change rethought.
//
//   npm run reverify                        every run not yet retired, from the production D1 and R2
//   npm run reverify -- <dir>               the .crd files in <dir>
//   npm run reverify -- --public <out>      CI: every ranked run, from the public site, into <out>'s verdicts
//   npm run reverify -- --verdicts <dir>    deploy: production's runs, taking the verdicts CI left in <dir>
//
// Production is only read, through wrangler and r2.mjs: the runs that fail are listed, with SQL to retire them for a
// migration. Each run that verifies also gets its ground baked (src/ground.ts) from the built site's art (dist/ui),
// into .reverify/grounds/ for `npm run grounds` to put in production once the build is deployed.
//
// --public keeps the replays in .reverify-public/, and <out> holds verdicts.json ({inputs, runs: {id: {ok, reason}}},
// for these replay inputs: deploy-replays.mjs) with grounds/. Both hold only what the public site serves, so CI may
// cache them; .reverify/ also holds hidden and banned runs' replays and must not enter Actions caches. A run <out>
// already has a verdict for under the same inputs is not replayed again, and a failure passes only while a migration
// names the run, to retire it in the same change. --verdicts replays only the runs CI did not see: those accepted
// since, and hidden or banned ones.
// Runs verify on one worker thread per CPU (reverify-worker.mjs).
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { availableParallelism } from "node:os";
import { replayInputs } from "./deploy-replays.mjs";
import { downloadReplays } from "./reverify-cache.mjs";
import { verifyRuns } from "./reverify-pool.mjs";
import { r2Bucket } from "./r2.mjs";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const CORE = join(SERVICE, "../crimson-core/build/wasm/core.wasm");
const CACHE = join(SERVICE, ".reverify");
const GROUNDS = join(CACHE, "grounds");
const PUBLIC = join(SERVICE, ".reverify-public");
const MIGRATIONS = join(SERVICE, "migrations");
const ART = join(SERVICE, "dist");
const ORIGIN = "https://crimson.land";

const elapsed = (start) => `${((performance.now() - start) / 1000).toFixed(2)}s`;

const wrangler = (...args) =>
  execFileSync("npx", ["--no-install", "wrangler", ...args, "--remote", "--config", join(SERVICE, "wrangler.jsonc")], {
    cwd: SERVICE,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });

// The runs `verdicts` already settles, with their verdicts, and the rest of `ids`, still to verify.
export function settle(ids, verdicts) {
  return {
    settled: ids.filter((id) => Object.hasOwn(verdicts, id)).map((id) => ({ id, ...verdicts[id] })),
    unsettled: ids.filter((id) => !Object.hasOwn(verdicts, id)),
  };
}

// The failures no migration retires: a change that breaks runs retires them in that same change.
export const unexpectedFailures = (results, migrations) => results.filter(({ id, ok }) => !ok && !migrations.includes(id));

// Production's runs not yet retired.
function activeRuns() {
  const [{ results }] = JSON.parse(wrangler("d1", "execute", "crimson-land", "--json", "--command", "SELECT id FROM runs WHERE retired IS NULL"));
  return results.map(({ id }) => id);
}

// Each run's replay as {id, file}, fetched once into `directory` by `get`.
async function fetchReplays(ids, directory, get) {
  const start = performance.now();
  const { runs, downloaded } = await downloadReplays(ids, directory, async (id, file) => writeFileSync(file, await get(id)), 16);
  console.log(`Replays: ${downloaded} downloaded, ${runs.length - downloaded} cached in ${elapsed(start)}`);
  return runs;
}

function fromR2(ids) {
  const bucket = r2Bucket();
  return fetchReplays(ids, CACHE, (id) => bucket.get(`runs/${id}.crd`));
}

async function fromSite(path) {
  const response = await fetch(`${ORIGIN}${path}`, { signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw Error(`GET ${ORIGIN}${path}: HTTP ${response.status}`);
  return response;
}

// Removes the files in `directory` other than those of `ids`.
function prune(directory, ids, extension) {
  if (!existsSync(directory)) return;
  const keep = new Set(ids.map((id) => `${id}${extension}`));
  for (const name of readdirSync(directory)) if (!keep.has(name)) rmSync(join(directory, name), { recursive: true, force: true });
}

// Verifies `runs`, baking each verified run's ground into `grounds`.
async function verify(runs, grounds) {
  mkdirSync(grounds, { recursive: true });
  const start = performance.now();
  const results = await verifyRuns(runs, {
    jobs: availableParallelism(),
    workerData: { service: SERVICE, art: ART, grounds },
    onResult: ({ id, ok, reason, seconds, ticks }) => console.log(`${id}  ${ok ? "ok" : reason}  ${seconds.toFixed(2)}s (${ticks} ticks)`),
  });
  console.log(`${runs.length} runs replayed in ${elapsed(start)}.`);
  return results.map(({ id, ok, reason }) => ({ id, ok, reason }));
}

function report(results, blocking) {
  const failed = results.filter(({ ok }) => !ok).length;
  console.log(`\n${results.length - failed} of ${results.length} runs verify.`);
  if (failed > blocking.length) console.log(`${failed - blocking.length} that do not are retired by a migration.`);
  if (!blocking.length) return;
  console.log("To retire the rest (write each reason for players):");
  for (const { id, reason } of blocking) console.log(`UPDATE runs SET retired = '${reason.replaceAll("'", "''")}' WHERE id = '${id}';`);
  process.exitCode = 1;
}

async function reverifyPublic(out) {
  const inputs = await replayInputs();
  const file = join(out, "verdicts.json");
  const grounds = join(out, "grounds");
  const previous = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
  const { runs: listed } = await (await fromSite("/api/replays")).json();
  const { settled, unsettled } = settle(listed, previous?.inputs === inputs ? previous.runs : {});
  // Only what the site still serves stays: a run hidden, banned, retired or deleted since leaves the caches.
  prune(PUBLIC, listed, ".crd");
  prune(grounds, settled.map(({ id }) => id), ".jpg");
  const runs = await fetchReplays(unsettled, PUBLIC, async (id) => new Uint8Array(await (await fromSite(`/runs/${id}.crd`)).arrayBuffer()));
  const results = [...settled, ...(await verify(runs, grounds))];
  writeFileSync(file, `${JSON.stringify({ inputs, runs: Object.fromEntries(results.map(({ id, ok, reason }) => [id, { ok, reason }])) })}\n`);
  console.log(`${settled.length} verdicts kept for these replay inputs, ${runs.length} runs replayed.`);
  const migrations = readdirSync(MIGRATIONS).map((name) => readFileSync(join(MIGRATIONS, name), "utf8")).join("\n");
  report(results, unexpectedFailures(results, migrations));
}

async function reverifyDelta(dir) {
  const { inputs, runs: verdicts } = JSON.parse(readFileSync(join(dir, "verdicts.json"), "utf8"));
  assert.equal(inputs, await replayInputs(), "CI's verdicts are for other replay inputs");
  const { settled, unsettled } = settle(activeRuns(), verdicts);
  for (const { id, ok } of settled) if (ok) copyFileSync(join(dir, "grounds", `${id}.jpg`), join(GROUNDS, `${id}.jpg`));
  const results = [...settled, ...(await verify(await fromR2(unsettled), GROUNDS))];
  console.log(`${settled.length} runs settled by CI's verdicts, ${unsettled.length} verified here.`);
  report(results, results.filter(({ ok }) => !ok));
}

async function main() {
  if (!existsSync(CORE)) throw Error(`build the core first: uv run python crimson-core/build.py --target wasm (${CORE})`);
  if (!existsSync(join(ART, "ui"))) throw Error(`build the site first: npm run assets && npm run build (${ART})`);
  const [mode, dir] = process.argv.slice(2);
  if (mode === "--public") return reverifyPublic(dir);
  rmSync(GROUNDS, { recursive: true, force: true });
  mkdirSync(GROUNDS, { recursive: true });
  if (mode === "--verdicts") return reverifyDelta(dir);
  const runs = mode
    ? readdirSync(mode).filter((name) => name.endsWith(".crd")).map((name) => ({ id: name.slice(0, -4), file: join(mode, name) }))
    : await fromR2(activeRuns());
  const results = await verify(runs, GROUNDS);
  report(results, results.filter(({ ok }) => !ok));
  console.log(`Their grounds are in ${GROUNDS}.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
