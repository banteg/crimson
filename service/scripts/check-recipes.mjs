// The production workflow can read D1 and write the replay bucket. It gives each candidate to
// a bounded compiler process without credentials. Only the owning Worker updates the D1 row.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { r2Bucket } from "./r2.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const service = fileURLToPath(new URL("../", import.meta.url));
const list = "SELECT id, source_revision, source, seed, title, author, digest FROM custom_quests " +
  "WHERE source IS NOT NULL AND source_state = 'pending' ORDER BY created_at, id LIMIT 16";
const origin = "https://crimson.land";

export function checkRecipe(candidate, python = `${root}.venv/${process.platform === "win32" ? "Scripts/python.exe" : "bin/python"}`) {
  const child = spawnSync(python, ["service/scripts/check_recipe.py"], {
    cwd: root, env: { PATH: process.env.PATH, PYTHONUTF8: "1" }, timeout: 15000,
    input: JSON.stringify(candidate), encoding: "utf8", maxBuffer: 8192,
  });
  if (child.error || child.status !== 0) throw Error("Recipe compiler did not finish successfully", { cause: child.error });
  const verdict = child.stdout.trim();
  assert.ok(verdict === "verified" || verdict === "rejected", "Invalid compiler result");
  return verdict;
}

export async function reconcileRecipes(rows, put, settle, compiler, compile = checkRecipe) {
  assert.match(compiler, /^[a-f0-9]{40}$/);
  const failures = [];
  for (const { id, source_revision, ...candidate } of rows) {
    try {
      assert.match(id, /^[a-f0-9]{12}$/);
      assert.match(source_revision, /^[a-f0-9]{32}$/);
      const key = `recipe-checks/${source_revision}`;
      await put(key, JSON.stringify({ state: compile(candidate), compiler }), "application/json");
      await settle(id, key);
    } catch (error) {
      failures.push(new Error(`Recipe check failed for ${id}`, { cause: error }));
    }
  }
  if (failures.length) throw new AggregateError(failures, "Some recipe checks need to be retried");
}

async function main() {
  // Never use a compiler checkout that differs from the service currently serving these recipes.
  const live = await fetch(`${origin}/deployment.txt`, { cache: "no-store", signal: AbortSignal.timeout(15000) });
  assert.ok(live.ok, "Could not identify the deployed service");
  const compiler = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  assert.equal((await live.text()).trim(), compiler);
  const output = execFileSync("npx", ["--no-install", "wrangler", "d1", "execute", "crimson-land", "--remote", "--json", "--command", list], {
    cwd: service, encoding: "utf8", maxBuffer: 16 << 20,
  });
  const [{ results }] = JSON.parse(output);
  const bucket = r2Bucket();
  await reconcileRecipes(results, bucket.put, async (id, key) => {
    const response = await fetch(`${origin}/api/custom/${id}`, { cache: "no-store", signal: AbortSignal.timeout(30000) });
    await response.body?.cancel();
    if (response.status === 404) await bucket.remove(key);
    else assert.ok(response.ok, "The service could not apply a recipe check");
  }, compiler);
  console.log(`Checked ${results.length} recipe candidates.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
