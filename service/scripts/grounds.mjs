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
  const before = new Set((await runs()).map(({ id }) => id));
  const kept = baked.filter((id) => before.has(id));
  await pool(kept, put, concurrency);
  const after = await runs();
  const present = new Set(after.map(({ id }) => id));
  const removed = kept.filter((id) => !present.has(id));
  await pool(removed, remove, concurrency);
  const known = new Set(baked);
  const newer = after.filter(({ id, retired }) => !retired && !known.has(id)).map(({ id }) => id);
  const failed = [];
  for (const id of newer) if (!(await bake(id))) failed.push(id);
  return { put: kept.length, removed: removed.length, baked: newer.length - failed.length, failed };
}

async function main() {
  const wrangler = (...args) => execFileAsync("npx", ["--no-install", "wrangler", ...args, "--remote", "--config", join(SERVICE, "wrangler.jsonc")], { cwd: SERVICE });
  const bucket = r2Bucket();
  const key = (id) => `runs/${id}.ground.jpg`;
  const started = performance.now();
  const result = await putGrounds({
    baked: readdirSync(GROUNDS).filter((name) => name.endsWith(".jpg")).map((name) => name.slice(0, -4)),
    runs: async () => JSON.parse((await wrangler("d1", "execute", "crimson-land", "--json", "--command", "SELECT id, retired FROM runs")).stdout)[0].results,
    put: (id) => bucket.put(key(id), readFileSync(join(GROUNDS, `${id}.jpg`)), "image/jpeg"),
    remove: (id) => bucket.remove(key(id)),
    bake: async (id) => (await fetch(`${ORIGIN}/runs/${id}.ground.jpg`, { signal: AbortSignal.timeout(120000) })).ok,
  });
  console.log(`${result.put} grounds put, ${result.removed} removed for deleted runs, ${result.baked} baked by the service for newer runs, in ${((performance.now() - started) / 1000).toFixed(2)}s.`);
  if (result.failed.length) {
    console.log(`The service could not bake these runs' grounds (do they still verify?): ${result.failed.join(", ")}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
