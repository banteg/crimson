// Puts the grounds `npm run reverify` baked (.reverify/grounds/) into production's R2 once that build is deployed:
// every unretired run's, so each run's card and page draw the ground the deployed service bakes (src/ground.ts),
// and no run's first view waits for its replay to be verified again.
//
//   npm run grounds
import { execFile, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const GROUNDS = join(SERVICE, ".reverify/grounds");
const CONCURRENCY = 4;
const execFileAsync = promisify(execFile);
const wrangler = (...args) => ["--no-install", "wrangler", ...args, "--remote", "--config", join(SERVICE, "wrangler.jsonc")];

const [{ results }] = JSON.parse(
  execFileSync("npx", wrangler("d1", "execute", "crimson-land", "--json", "--command", "SELECT id FROM runs WHERE retired IS NULL"), {
    cwd: SERVICE,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  }),
);
const missing = results.filter(({ id }) => !existsSync(join(GROUNDS, `${id}.jpg`)));
if (missing.length) throw Error(`no baked ground for ${missing.length} runs: run npm run reverify first (${missing.map(({ id }) => id).join(", ")})`);

const started = performance.now();
let next = 0;
await Promise.all(
  Array.from({ length: CONCURRENCY }, async () => {
    while (next < results.length) {
      const { id } = results[next++];
      await execFileAsync("npx", wrangler("r2", "object", "put", `crimson-land-replays/runs/${id}.ground.jpg`,
        "--file", join(GROUNDS, `${id}.jpg`), "--content-type", "image/jpeg"), { cwd: SERVICE });
    }
  }),
);
console.log(`${results.length} grounds put in ${((performance.now() - started) / 1000).toFixed(2)}s.`);
