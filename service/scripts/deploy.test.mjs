import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { downloadReplays } from "./reverify-cache.mjs";
import { requireArtifacts, requireGreenChecks, requireTrustedRun, REQUIRED_CHECKS } from "./deploy-preflight.mjs";
import { requireMigrations, packageManifest, verifyManifest, smoke, waitForRelease } from "./deploy-checks.mjs";

const sha = "a".repeat(40);
const run = { head_repository: { full_name: "banteg/crimson" }, head_branch: "master", head_sha: sha, path: ".github/workflows/core.yml", event: "push", status: "completed", conclusion: "success" };
const checks = REQUIRED_CHECKS.map((name, id) => ({ id, name, app: { slug: "github-actions" }, status: "completed", conclusion: "success" }));
const artifacts = ["runtime-wasm", "crimsonland-web"].map((name, index) => ({ id: index + 1, name, expired: false, size_in_bytes: 100, workflow_run: { head_sha: sha } }));

test("requires every check, rejects external checks and failed newer reruns", () => {
  requireGreenChecks(checks);
  assert.throws(() => requireGreenChecks(checks.slice(1)), /ast-grep/);
  assert.throws(() => requireGreenChecks(checks.map((check) => ({ ...check, app: { slug: "another-app" } }))), /missing/);
  for (const state of [{ status: "in_progress", conclusion: null }, { status: "completed", conclusion: "failure" }, { status: "completed", conclusion: "skipped" }]) {
    assert.throws(() => requireGreenChecks([...checks, { ...checks[0], id: 100, ...state }]), /ast-grep/);
  }
});

test("accepts only successful same-commit runtime builds from this repository's master", () => {
  requireTrustedRun(run, "banteg/crimson", sha);
  requireTrustedRun({ ...run, event: "workflow_dispatch" }, "banteg/crimson", sha);
  for (const patch of [
    { head_repository: { full_name: "fork/crimson" } }, { head_branch: "feature" }, { head_sha: "b".repeat(40) },
    { path: ".github/workflows/another.yml" }, { event: "pull_request" }, { status: "in_progress" }, { conclusion: "failure" },
  ]) assert.throws(() => requireTrustedRun({ ...run, ...patch }, "banteg/crimson", sha));
});

test("pins the newest artifact IDs across job reruns and refuses invalid newest artifacts", () => {
  assert.deepEqual(requireArtifacts(artifacts, sha), { "runtime-wasm": 1, "crimsonland-web": 2 });
  assert.throws(() => requireArtifacts(artifacts.slice(1), sha), /runtime-wasm/);
  const newer = { ...artifacts[0], id: 100 };
  assert.deepEqual(requireArtifacts([newer, ...artifacts], sha), { "runtime-wasm": 100, "crimsonland-web": 2 });
  for (const patch of [{ expired: true }, { size_in_bytes: 0 }, { workflow_run: { head_sha: "b".repeat(40) } }]) {
    assert.throws(() => requireArtifacts([...artifacts, { ...newer, ...patch }], sha));
  }
  assert.throws(() => requireArtifacts([{ ...artifacts[0], id: "1" }, artifacts[1]], sha), /Invalid.*ID/);
  for (const patch of [{ expired: true }, { size_in_bytes: 0 }, { workflow_run: { head_sha: "b".repeat(40) } }]) {
    assert.throws(() => requireArtifacts([{ ...artifacts[0], ...patch }, artifacts[1]], sha));
  }
});

test("blocks pending or unknown production migrations and malformed query results", () => {
  const remote = [{ success: true, results: [{ name: "0001.sql" }] }];
  requireMigrations(["0001.sql"], remote);
  assert.throws(() => requireMigrations(["0001.sql", "0002.sql"], remote), /0002.sql/);
  assert.throws(() => requireMigrations([], remote), /absent/);
  for (const invalid of [[], [{ success: false, results: [] }], { results: [] }]) {
    assert.throws(() => requireMigrations(["0001.sql"], invalid), /Invalid/);
  }
});


test("release manifest requires a complete package and detects tampering or a different commit", () => {
  const root = mkdtempSync(join(tmpdir(), "crimson-release-"));
  const previous = process.cwd();
  try {
    mkdirSync(join(root, "service"));
    process.chdir(join(root, "service"));
    writeFileSync("../release.json", JSON.stringify({ sha }));
    assert.throws(() => packageManifest(), /ENOENT/);
    const files = ["dist/index.html", "dist/play/index.html", "dist/play/index.js", "dist/play/index.wasm", "dist/ui/small.ttf", "dist/ui/small.woff2", "release-worker/index.js", "../crimson-core/build/wasm/core.wasm", "wrangler.jsonc"];
    for (const file of files) {
      mkdirSync(join(file, ".."), { recursive: true });
      writeFileSync(file, "fixture");
    }
    packageManifest();
    verifyManifest(sha);
    assert.equal(readFileSync("dist/deployment.txt", "utf8").trim(), sha);
    assert.throws(() => verifyManifest("b".repeat(40)), /another commit/);
    writeFileSync("dist/extra.txt", "unexpected");
    assert.throws(() => verifyManifest(sha), /file list changed/);
    rmSync("dist/extra.txt");
    writeFileSync("dist/play/index.wasm", "changed");
    assert.throws(() => verifyManifest(sha), /Changed release file/);
  } finally {
    process.chdir(previous);
    rmSync(root, { recursive: true, force: true });
  }
});

test("production smoke rejects another release, HTML instead of game files and missing archives", async () => {
  const responseFor = (url) => {
    const path = new URL(url).pathname;
    if (path === "/deployment.txt") return new Response(sha);
    if (path.startsWith("/api/")) return Response.json({ board: "survival" });
    if (path.endsWith(".wasm")) return new Response(new Uint8Array([0, 97, 115, 109]));
    if (path.endsWith(".js")) return new Response("game", { headers: { "Content-Type": "application/javascript" } });
    return new Response("ok");
  };
  await smoke("https://example.test", sha, responseFor);
  await assert.rejects(smoke("https://example.test", "b".repeat(40), responseFor, { timeoutMs: 0 }), /another release/);
  for (const path of ["/play/index.js", "/play/index.wasm", "/play/game/music.paq"]) {
    await assert.rejects(smoke("https://example.test", sha, (url) => {
      if (new URL(url).pathname === path) return new Response("<html>", { status: path.endsWith(".paq") ? 404 : 200 });
      return responseFor(url);
    }));
  }
});


test("waits for propagation through old releases, HTTP failures and transient network errors", async () => {
  let time = 0;
  const polling = { timeoutMs: 6000, intervalMs: 2000, now: () => time, pause: async (ms) => { time += ms; } };
  const attempts = [() => { throw new Error("connection reset"); }, () => new Response("unavailable", { status: 503 }), () => new Response("old"), () => new Response(sha)];
  await waitForRelease("https://example.test", sha, async () => attempts.shift()(), polling);
  assert.equal(time, 6000);
  assert.equal(attempts.length, 0);
  time = 0;
  await assert.rejects(waitForRelease("https://example.test", sha, async () => new Response("old"), polling), /Timed out.*another release/);
  assert.equal(time, 6000);
});


test("replay downloads are bounded, reuse complete files, and never keep failed partial files", async () => {
  const directory = mkdtempSync(join(tmpdir(), "crimson-replays-"));
  const ids = Array.from({ length: 5 }, (_, index) => String(index).repeat(64));
  let active = 0, maximum = 0;
  try {
    const fetchReplay = async (id, file) => {
      maximum = Math.max(maximum, ++active);
      await new Promise((resolve) => setImmediate(resolve));
      writeFileSync(file, id);
      active--;
    };
    const { runs, downloaded } = await downloadReplays(ids, directory, fetchReplay, 2);
    assert.equal(downloaded, 5);
    assert.equal(maximum, 2);
    assert.equal(runs.length, 5);
    const cached = await downloadReplays(ids, directory, async () => { throw Error("should reuse completed downloads"); });
    assert.equal(cached.downloaded, 0);
    rmSync(runs[0].file);
    await assert.rejects(downloadReplays(ids, directory, async (_, file) => {
      writeFileSync(file, "partial");
      throw Error("download failed");
    }), /download failed/);
    assert.equal(existsSync(runs[0].file), false);
    assert.equal(existsSync(`${runs[0].file}.partial`), false);
    await assert.rejects(downloadReplays(["../bad"], directory, fetchReplay), /Invalid production run ID/);
    await assert.rejects(downloadReplays(ids, directory, fetchReplay, 0), /Invalid download concurrency/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
