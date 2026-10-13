import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { downloadReplays } from "./reverify-cache.mjs";
import { verifyRuns } from "./reverify-pool.mjs";
import { putGrounds } from "./grounds.mjs";
import { r2Bucket } from "./r2.mjs";
import { replayInputs, replayPlan } from "./deploy-replays.mjs";
import { requireArtifacts, requireGreenChecks, requireTrustedRun, resolveRuntimeBuild, REQUIRED_CHECKS } from "./deploy-preflight.mjs";
import { requireBuildIdentity, requireMigrations, packageManifest, verifyManifest, smoke, waitForRelease } from "./deploy-checks.mjs";

const sha = "a".repeat(40);
const run = { head_repository: { full_name: "banteg/crimson" }, head_branch: "master", head_sha: sha, path: ".github/workflows/core.yml", event: "push", status: "completed", conclusion: "success" };
const checks = REQUIRED_CHECKS.map((name, id) => ({ id, name, app: { slug: "github-actions" }, status: "completed", conclusion: "success" }));
const artifacts = ["runtime-wasm", "crimsonland-web"].map((name, index) => ({ id: index + 1, name, expired: false, size_in_bytes: 100, workflow_run: { head_sha: sha } }));

const service = join(import.meta.dirname, "..");
test("parallel reverification matches serial verdicts and ground JPEGs, and aborts on a replay it cannot run", {
  skip: !existsSync(join(service, "dist/ui/particles.png")) || !existsSync(join(service, "../crimson-core/build/wasm/core.wasm")),
  timeout: 60000,
}, async () => {
  const directory = mkdtempSync(join(tmpdir(), "crimson-reverify-"));
  try {
    const vectors = JSON.parse(readFileSync(join(service, "test/vectors.json"), "utf8"));
    const refused = join(directory, "refused.crd");
    writeFileSync(refused, Buffer.from(vectors.illegal_command_run, "base64"));
    const runs = [
      { id: "quest", file: join(service, "../tests/fixtures/replays/quest-1.1-completed.crd") },
      { id: "refused", file: refused },
      { id: "rush", file: join(service, "../tests/fixtures/replays/rush-kills103.crd") },
    ];
    const check = async (jobs) => {
      const grounds = join(directory, String(jobs));
      mkdirSync(grounds);
      const results = await verifyRuns(runs, { jobs, workerData: { service, art: join(service, "dist"), grounds } });
      assert.deepEqual(results.map(({ ok }) => ok), [true, false, true]);
      assert.equal(existsSync(join(grounds, "refused.jpg")), false);
      return {
        verdicts: results.map(({ seconds, ...result }) => result),
        grounds: ["quest", "rush"].map((id) => createHash("sha256").update(readFileSync(join(grounds, `${id}.jpg`))).digest("hex")),
      };
    };
    assert.deepEqual(await check(2), await check(1));
    const unsupported = { id: "typo", file: join(service, "../tests/fixtures/replays/typo-144.crd") };
    await assert.rejects(verifyRuns([...runs, unsupported], { jobs: 2, workerData: { service, art: join(service, "dist"), grounds: directory } }), /Failed to reverify typo/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function build(kind, artifactFiles, game = null) {
  // Keys are inserted in the canonical order shared with the Python planner.
  const recipe = game ? { game: game.artifacts["game.wasm"], version: "1.2.3" } : { version: "1.2.3" };
  const payload = { inputs: {}, kind, recipe, schema: 1 };
  const fingerprint = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  return { ...payload, fingerprint, version: `1.2.3+build.${fingerprint.slice(0, 24)}`, origin: { commit: sha, dirty: false },
    artifacts: Object.fromEntries(artifactFiles.map(([name, contents]) => [name, createHash("sha256").update(contents).digest("hex")])), ...(game ? { game } : {}) };
}

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
    const game = build("game", [["game.wasm", "game module"]]);
    writeFileSync("../crimson-core/build/wasm/core.wasm.build.json", JSON.stringify(build("wasm", [["core.wasm", "fixture"]])));
    writeFileSync("dist/play/build.json", JSON.stringify(build("client", ["index.html", "index.js", "index.wasm"].map((name) => [name, "fixture"]), game)));
    packageManifest();
    verifyManifest(sha);
    assert.equal(readFileSync("dist/deployment.txt", "utf8").trim(), sha);
    assert.throws(() => verifyManifest("b".repeat(40)), /another commit/);
    writeFileSync("dist/extra.txt", "unexpected");
    assert.throws(() => verifyManifest(sha), /file list changed/);
    rmSync("dist/extra.txt");
    writeFileSync("dist/play/index.wasm", "changed");
    assert.throws(() => verifyManifest(sha), /Changed build artifact/);
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


test("reuses a successful same-commit build without dispatching new CI", async () => {
  const request = async (path) => {
    if (path.startsWith("actions/workflows/core.yml/runs?")) return { workflow_runs: [{ ...run, id: 123 }] };
    assert.ok(path.startsWith("actions/runs/123/artifacts?"));
    return { artifacts };
  };
  const release = await resolveRuntimeBuild("banteg/crimson", sha, "", { request });
  assert.equal(release.runtime_run_id, 123);
  assert.deepEqual(release.artifacts, { "runtime-wasm": 1, "crimsonland-web": 2 });
});

test("requests only release producers when artifacts are missing, then pins the completed build", async () => {
  let dispatched = false, time = 0;
  const request = async (path, options) => {
    if (path === "branches/master") return { commit: { sha } };
    if (path.endsWith("/dispatches")) {
      assert.equal(options.method, "POST");
      assert.deepEqual(JSON.parse(options.body), { ref: "master", inputs: { release_only: true } });
      dispatched = true;
      return null;
    }
    if (path.startsWith("actions/workflows/core.yml/runs?")) return { workflow_runs: [{ ...run, id: dispatched ? 456 : 123 }] };
    return { artifacts: dispatched ? artifacts : artifacts.slice(1) };
  };
  const release = await resolveRuntimeBuild("banteg/crimson", sha, "", {
    request, now: () => time, pause: async (ms) => { time += ms; }, intervalMs: 2000,
  });
  assert.equal(dispatched, true);
  assert.equal(release.runtime_run_id, 456);
  assert.equal(time, 2000);
});

test("artifact build waits are bounded and reject advancing master or invalid explicit run IDs", async () => {
  let time = 0;
  const request = async (path) => {
    if (path === "branches/master") return { commit: { sha: time ? "b".repeat(40) : sha } };
    if (path.endsWith("/dispatches")) return null;
    if (path.startsWith("actions/workflows/core.yml/runs?")) return { workflow_runs: [] };
    return { ...run, event: "pull_request" };
  };
  const options = { request, now: () => time, pause: async (ms) => { time += ms; }, timeoutMs: 2000, intervalMs: 1000 };
  await assert.rejects(resolveRuntimeBuild("banteg/crimson", sha, "", options), /superseded/);
  time = 0;
  await assert.rejects(resolveRuntimeBuild("banteg/crimson", sha, "", {
    ...options, request: async (path) => path === "branches/master" ? { commit: { sha } } : request(path),
  }), /Timed out/);
  assert.equal(time, 2000);
  await assert.rejects(resolveRuntimeBuild("banteg/crimson", sha, "123", options), /PR builds/);
  await assert.rejects(resolveRuntimeBuild("banteg/crimson", sha, "bad", options), /must be numeric/);
});


test("build fingerprints preserve origin and reject identity, label or dirty-source tampering", () => {
  const original = build("game", [["game.wasm", "module"]]);
  requireBuildIdentity(original, "game");
  requireBuildIdentity({ ...original, origin: { commit: "b".repeat(40), dirty: false } }, "game");
  assert.throws(() => requireBuildIdentity({ ...original, recipe: { version: "9.9.9" } }, "game"), /Changed build identity/);
  assert.throws(() => requireBuildIdentity({ ...original, version: "fake" }, "game"), /Wrong build label/);
  assert.throws(() => requireBuildIdentity({ ...original, origin: { commit: sha, dirty: true } }, "game"), /modified inputs/);
});

test("puts the grounds of runs production still has, removes those deleted meanwhile and has newer runs baked", async () => {
  // x was deleted before the deploy, b while its ground went up; c and d came after the bake, e retired.
  const snapshots = [
    ["a", "b", "c"].map((id) => ({ id, retired: null })),
    [{ id: "a", retired: null }, { id: "c", retired: null }, { id: "d", retired: null }, { id: "e", retired: "refused" }],
  ];
  const calls = { put: [], remove: [], bake: [] };
  const result = await putGrounds({
    baked: ["a", "b", "x"],
    runs: async () => snapshots.shift(),
    put: async (id) => calls.put.push(id),
    remove: async (id) => calls.remove.push(id),
    bake: async (id) => calls.bake.push(id) && id !== "d",
  });
  assert.deepEqual(calls, { put: ["a", "b"], remove: ["b"], bake: ["c", "d"] });
  assert.deepEqual(result, { put: 2, removed: 1, baked: 1, failed: ["d"] });
});

// The replay identity must cover what executes, not a hand-maintained path filter.

function replayFixture() {
  const directory = mkdtempSync(join(tmpdir(), "crimson-replay-inputs-"));
  const service = join(directory, "service");
  const files = {
    "src/verify.ts": 'import core from "../../crimson-core/build/wasm/core.wasm"; import { aim } from "./aim"; import schema from "./schema.json"; export function verifyRun() { return [core, aim(), schema.fields]; }',
    "src/aim.ts": 'export const aim = () => 1;',
    "src/schema.json": '{"fields":1}',
    "src/replay.ts": 'export const REPLAY_RULES = 1; export const decodeReplay = (x) => x; export const inflateReplay = (x) => x;',
    "src/transport.ts": 'export const encodeTransport = (x) => x;',
    "src/ranked.ts": 'export const unrankedReasons = () => []; export const outcomeReasons = () => []; export const rankedBoard = () => "survival"; export const rankedScore = () => 1;',
    "src/ground.ts": 'export const paint = () => 1; export const groundKey = (id) => `runs/${id}.jpg`;',
    "src/runs.ts": 'import { verifyRun } from "./verify"; import { paint } from "./ground"; export const verifyWithGround = () => [verifyRun(), paint()];',
    "src/ground-art.json": '{"terrain":["ter0.png"],"particles":"particles.png","bodyset":"bodyset.png"}',
    "package-lock.json": '{"lockfileVersion":3}',
    "package.json": '{"type":"module"}',
    "scripts/deploy-replays.mjs": "planner",
    "scripts/reverify.mjs": "reverify runner",
    "scripts/reverify-pool.mjs": "worker pool",
    "scripts/reverify-worker.mjs": "verification worker",
    "scripts/grounds.mjs": "ground upload",
    "wrangler.jsonc": '{"compatibility_date":"2026-08-22"}',
    "migrations/0001.sql": 'CREATE TABLE runs (id TEXT);',
    "dist/ui/ter0.png": "terrain",
    "dist/ui/particles.png": "particles",
    "dist/ui/bodyset.png": "corpses",
    "../crimson-core/build/wasm/core.wasm": new Uint8Array([0, 97, 115, 109]),
  };
  const write = (file, contents) => {
    mkdirSync(join(service, file, ".."), { recursive: true });
    writeFileSync(join(service, file), contents);
  };
  for (const [file, contents] of Object.entries(files)) write(file, contents);
  return { directory, service, write };
}

test("replay identity ignores metadata, page styles and client code, and checkout paths", async () => {
  const a = replayFixture(), b = replayFixture();
  try {
    const before = await replayInputs(a.service);
    assert.equal(await replayInputs(b.service), before);
    for (const file of ["src/index.ts", "dist/index.html", "dist/style.css", "dist/play/index.js", "dist/ui/menu.png"])
      a.write(file, "presentation changed");
    assert.equal(await replayInputs(a.service), before);
  } finally { rmSync(a.directory, { recursive: true, force: true }); rmSync(b.directory, { recursive: true, force: true }); }
});

test("replay identity changes with WASM, rules, new transitive modules, ground rendering, art, scripts and dependencies", async () => {
  const fixture = replayFixture();
  try {
    let previous = await replayInputs(fixture.service);
    for (const [file, contents] of [
      ["../crimson-core/build/wasm/core.wasm", new Uint8Array([0, 97, 115, 109, 1])],
      ["src/schema.json", '{"fields":2}'],
      ["src/ranked.ts", 'export const unrankedReasons = () => ["new rule"]; export const outcomeReasons = () => []; export const rankedBoard = () => "survival"; export const rankedScore = () => 1;'],
      ["src/aim.ts", 'import { bound } from "./bound"; export const aim = () => bound;'],
      ["src/bound.ts", 'export const bound = 3;'],
      ["src/ground.ts", 'export const paint = () => 2; export const groundKey = (id) => `runs/${id}.jpg`;'],
      ["dist/ui/particles.png", "different pixels"],
      ["scripts/grounds.mjs", "new upload policy"],
      ["scripts/reverify-worker.mjs", "new verification setup"],
      ["package-lock.json", '{"lockfileVersion":3,"version":"changed"}'],
      ["wrangler.jsonc", '{"compatibility_date":"2026-09-01"}'],
      ["migrations/0002.sql", 'ALTER TABLE runs ADD hidden INTEGER;'],
    ]) {
      if (file === "src/aim.ts") fixture.write("src/bound.ts", 'export const bound = 2;');
      fixture.write(file, contents);
      const current = await replayInputs(fixture.service);
      assert.notEqual(current, previous, file);
      previous = current;
    }
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test("reuses only the record of the commit production serves, unless forced", () => {
  const inputs = "1".repeat(64), record = { sha, inputs };
  assert.deepEqual(replayPlan(inputs, record, sha), { inputs, reuse: sha, reverify: false });
  for (const [current, stored, live] of [[inputs, null, sha], [inputs, record, null], [inputs, record, "b".repeat(40)], ["2".repeat(64), record, sha]])
    assert.equal(replayPlan(current, stored, live).reverify, true);
  assert.equal(replayPlan(inputs, record, sha, true).reverify, true);
});

test("R2 calls go to the replay bucket with the token, retry rate limits and server errors, and fail on the rest", async () => {
  const calls = [];
  const replies = [new Response("slow down", { status: 429, headers: { "retry-after": "0" } }), new Response("crd")];
  const bucket = r2Bucket(Promise.resolve({ token: "t", account: "acc" }), async (url, init) => {
    calls.push([init.method ?? "GET", url, init.headers.Authorization]);
    return replies.shift() ?? new Response("forbidden", { status: 403 });
  });
  assert.deepEqual(new TextDecoder().decode(await bucket.get("runs/a.crd")), "crd");
  const url = "https://api.cloudflare.com/client/v4/accounts/acc/r2/buckets/crimson-land-replays/objects/runs/a.crd";
  assert.deepEqual(calls, [["GET", url, "Bearer t"], ["GET", url, "Bearer t"]]);
  await assert.rejects(bucket.put("runs/a.ground.jpg", "jpeg", "image/jpeg"), /PUT runs\/a.ground.jpg: HTTP 403 forbidden/);
});
