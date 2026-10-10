import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

export function requireMigrations(local, remote) {
  assert.ok(Array.isArray(remote) && remote.length === 1 && remote[0].success === true, "Invalid migration query result");
  const applied = new Set(remote[0].results.map((row) => row.name));
  const pending = local.filter((name) => !applied.has(name));
  assert.equal(pending.length, 0, `Apply reviewed production migrations separately before deploying: ${pending.join(", ")}`);
  const unknown = [...applied].filter((name) => !local.includes(name));
  assert.equal(unknown.length, 0, `Production contains migrations absent from this commit: ${unknown.join(", ")}`);
}

export function packageFiles(directory) {
  return readdirSync(directory).sort().flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? packageFiles(path) : [path];
  });
}

export function packageManifest() {
  for (const path of ["dist/index.html", "dist/play/index.html", "dist/play/index.js", "dist/play/index.wasm", "dist/ui/small.ttf", "dist/ui/small.woff2", "release-worker/index.js"]) {
    assert.ok(statSync(path).size > 0, `Missing or empty deployment file: ${path}`);
  }
  const release = JSON.parse(readFileSync("../release.json", "utf8"));
  writeFileSync("dist/deployment.txt", `${release.sha}\n`);
  const files = [...packageFiles("dist"), ...packageFiles("release-worker"), "../crimson-core/build/wasm/core.wasm", "wrangler.jsonc"];
  const manifest = JSON.parse(readFileSync("../release.json", "utf8"));
  manifest.files = Object.fromEntries(files.map((path) => [path, createHash("sha256").update(readFileSync(path)).digest("hex")]));
  writeFileSync("../release.json", `${JSON.stringify(manifest, null, 2)}\n`);
}

export function verifyManifest(sha = process.env.GITHUB_SHA) {
  const manifest = JSON.parse(readFileSync("../release.json", "utf8"));
  assert.equal(manifest.sha, sha, "Release belongs to another commit");
  const expected = [...packageFiles("dist"), ...packageFiles("release-worker"), "../crimson-core/build/wasm/core.wasm", "wrangler.jsonc"].sort();
  assert.deepEqual(Object.keys(manifest.files).sort(), expected, "Release file list changed");
  for (const [path, hash] of Object.entries(manifest.files)) {
    assert.equal(createHash("sha256").update(readFileSync(path)).digest("hex"), hash, `Changed release file: ${path}`);
  }
}

// Wait for the uploaded release to reach the public route before checking its assets.
export async function waitForRelease(origin, sha, request = fetch, {
  timeoutMs = 60000, intervalMs = 2000, now = Date.now, pause = delay,
} = {}) {
  const deadline = now() + timeoutMs;
  let lastError;
  for (;;) {
    try {
      const response = await request(`${origin}/deployment.txt`, {
        headers: { "Cache-Control": "no-cache" },
        signal: AbortSignal.timeout(Math.max(1, Math.min(10000, deadline - now()))),
      });
      assert.equal(response.status, 200, `/deployment.txt: HTTP ${response.status}`);
      assert.equal((await response.text()).trim(), sha, "Production is serving another release");
      console.log("GET /deployment.txt: ok");
      return;
    } catch (error) {
      lastError = error;
    }
    const remaining = deadline - now();
    if (remaining <= 0) throw new Error(`Timed out waiting for production release ${sha}: ${lastError.message}`, { cause: lastError });
    await pause(Math.min(intervalMs, remaining));
  }
}

export async function smoke(origin = "https://crimson.land", sha = process.env.GITHUB_SHA, request = fetch, polling = {}) {
  await waitForRelease(origin, sha, request, polling);
  for (const path of ["/", "/api/boards/survival", "/play/", "/play/index.js", "/play/index.wasm", "/play/game/crimson.paq", "/play/game/sfx.paq", "/play/game/music.paq"]) {
    const head = path.endsWith(".paq");
    const response = await request(`${origin}${path}`, { method: head ? "HEAD" : "GET", headers: { "Cache-Control": "no-cache" }, signal: AbortSignal.timeout(30000) });
    assert.equal(response.status, 200, `${path}: HTTP ${response.status}`);
    if (path.endsWith(".js")) assert.match(response.headers.get("content-type") || "", /javascript/, "Game JS is not JavaScript");
    if (path.startsWith("/api/")) assert.ok((await response.json()).board, "Leaderboard did not return board JSON");
    if (path.endsWith(".wasm")) assert.deepEqual(new Uint8Array(await response.arrayBuffer()).slice(0, 4), new Uint8Array([0, 97, 115, 109]), "Game WASM is not a WASM file");
    console.log(`${head ? "HEAD" : "GET"} ${path}: ok`);
  }
}

async function main() {
  switch (process.argv[2]) {
    case "package": return packageManifest();
    case "verify": return verifyManifest();
    case "migrations": {
      const remote = JSON.parse(execFileSync("npx", ["--no-install", "wrangler", "d1", "execute", "crimson-land", "--remote", "--json", "--command", "SELECT name FROM d1_migrations ORDER BY id"], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }));
      return requireMigrations(readdirSync("migrations").filter((name) => name.endsWith(".sql")), remote);
    }
    case "smoke": return smoke();
    default: throw Error("Expected package, verify, migrations or smoke");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
