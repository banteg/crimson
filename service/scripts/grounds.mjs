// Puts the grounds `npm run reverify` baked (.reverify/grounds/) into production's R2 once that build is deployed, so
// each run's card and page draw the ground the deployed service bakes (src/ground.ts) and no run's first view waits
// for its replay to be verified again.
//
//   npm run grounds
//
// Production moves on while reverify and the deploy run: a run deleted since gets no ground (and loses one put while
// it went), and a run accepted since has the deployed service bake its own.
import { execFile } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { r2Bucket } from "./r2.mjs";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const GROUNDS = join(SERVICE, ".reverify/grounds");
const ORIGIN = "https://crimson.land";
const execFileAsync = promisify(execFile);

// `work` over `items`, `concurrency` at a time.
async function pool(items, work, concurrency) {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) await work(items[next++]);
  }));
}

// The baked grounds of runs production still has, put; then those of runs deleted meanwhile, removed; then the runs
// accepted since the bake (not retired), baked by the deployed service. `runs` lists production's runs as {id, retired};
// `bake` answers whether the service baked a run's ground.
export async function putGrounds({ baked, runs, put, remove, bake, concurrency = 16 }) {
  const byId = (rows) => new Map(rows.map(({ id, storage }) => [id, storage ?? id]));
  const before = byId(await runs());
  const kept = baked.filter((id) => before.has(id));
  await pool(kept, (id) => put(id, before.get(id)), concurrency);
  const after = await runs();
  const present = byId(after);
  const removed = kept.filter((id) => present.get(id) !== before.get(id));
  await pool(removed, (id) => remove(id, before.get(id)), concurrency);
  const known = new Set(kept.filter((id) => present.get(id) === before.get(id)));
  const newer = after.filter(({ id, retired }) => !retired && !known.has(id)).map(({ id }) => id);
  const failed = [];
  for (const id of newer) if (!(await bake(id))) failed.push(id);
  return { put: kept.length, removed: removed.length, baked: newer.length - failed.length, failed };
}

// A run hidden or deleted while previews are published has no public ground URL. An active
// private run still needs the ground already stored with its accepted replay.
export async function groundAfter404(id, current, visible, hasGround) {
  const row = (await current()).find((run) => run.id === id);
  if (!row || row.retired) return true;
  if ((await visible()).includes(id)) return false;
  return hasGround(row.storage);
}

async function main() {
  const wrangler = (...args) => execFileAsync("npx", ["--no-install", "wrangler", ...args, "--remote", "--config", join(SERVICE, "wrangler.jsonc")], { cwd: SERVICE });
  const bucket = r2Bucket();
  const key = (storage) => `runs/${storage}.ground.jpg`;
  const current = async () => JSON.parse((await wrangler("d1", "execute", "crimson-land", "--json", "--command",
    "SELECT id, retired, coalesce(storage_id, id) AS storage FROM runs")).stdout)[0].results;
  const visible = async () => {
    const response = await fetch(`${ORIGIN}/api/replays`, { cache: "no-store", signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw Error(`GET /api/replays: HTTP ${response.status}`);
    return (await response.json()).runs;
  };
  const started = performance.now();
  const result = await putGrounds({
    baked: readdirSync(GROUNDS).filter((name) => name.endsWith(".jpg")).map((name) => name.slice(0, -4)),
    runs: current,
    put: (id, storage) => bucket.put(key(storage), readFileSync(join(GROUNDS, `${id}.jpg`)), "image/jpeg"),
    remove: (_id, storage) => bucket.remove(key(storage)),
    bake: async (id) => {
      const response = await fetch(`${ORIGIN}/runs/${id}.ground.jpg`, { cache: "no-store", signal: AbortSignal.timeout(120000) });
      await response.body?.cancel();
      return response.status === 404
        ? groundAfter404(id, current, visible, async (storage) => (await bucket.get(key(storage))).length > 0)
        : response.ok;
    },
  });
  console.log(`${result.put} grounds put, ${result.removed} removed for deleted runs, ${result.baked} baked by the service for newer runs, in ${((performance.now() - started) / 1000).toFixed(2)}s.`);
  if (result.failed.length) {
    console.log(`The service could not bake these runs' grounds (do they still verify?): ${result.failed.join(", ")}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
