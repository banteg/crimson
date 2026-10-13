import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { downloadReplays } from "./reverify-cache.mjs";
import { putGrounds } from "./grounds.mjs";
import { replayInputs, replayPlan, beginReplayWork, productionSha, checkReplayPlan, recordReplayBaseline } from "./deploy-replays.mjs";
import { requireArtifacts, requireGreenChecks, requireTrustedRun, resolveRuntimeBuild, REQUIRED_CHECKS } from "./deploy-preflight.mjs";
import { requireBuildIdentity, requireMigrations, packageManifest, verifyManifest, smoke, waitForRelease } from "./deploy-checks.mjs";

const sha = "a".repeat(40);
const run = { head_repository: { full_name: "banteg/crimson" }, head_branch: "master", head_sha: sha, path: ".github/workflows/core.yml", event: "push", status: "completed", conclusion: "success" };
const checks = REQUIRED_CHECKS.map((name, id) => ({ id, name, app: { slug: "github-actions" }, status: "completed", conclusion: "success" }));
const artifacts = ["runtime-wasm", "crimsonland-web"].map((name, index) => ({ id: index + 1, name, expired: false, size_in_bytes: 100, workflow_run: { head_sha: sha } }));

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
    writeFileSync("release-worker/replay-inputs.json", JSON.stringify({ schema: 1, verification: "a".repeat(64), grounds: "b".repeat(64) }));
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

// Fingerprints must cover execution, not just the core's build label or a hand-maintained source path filter.

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
    "scripts/reverify.mjs": "reverify runner",
    "scripts/grounds.mjs": "ground upload",
    "wrangler.jsonc": '{ // comment\n"compatibility_date":"2026-08-22"}',
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

test("fingerprints exclude metadata, page styles and client code, and are independent of checkout paths", async () => {
  const a = replayFixture(), b = replayFixture();
  try {
    const before = await replayInputs(a.service);
    assert.deepEqual(await replayInputs(b.service), before);
    for (const file of ["src/index.ts", "dist/index.html", "dist/style.css", "dist/play/index.js", "dist/ui/menu.png"])
      a.write(file, "presentation changed");
    assert.deepEqual(await replayInputs(a.service), before);
  } finally { rmSync(a.directory, { recursive: true, force: true }); rmSync(b.directory, { recursive: true, force: true }); }
});

test("fingerprints invalidate for WASM, schema, rules, new transitive modules, dependencies, config and migrations", async () => {
  const fixture = replayFixture();
  try {
    let previous = await replayInputs(fixture.service);
    for (const [file, contents] of [
      ["../crimson-core/build/wasm/core.wasm", new Uint8Array([0, 97, 115, 109, 1])],
      ["src/schema.json", '{"fields":2}'],
      ["src/ranked.ts", 'export const unrankedReasons = () => ["new rule"]; export const outcomeReasons = () => []; export const rankedBoard = () => "survival"; export const rankedScore = () => 1;'],
      ["src/aim.ts", 'import { bound } from "./bound"; export const aim = () => bound;'],
      ["src/bound.ts", 'export const bound = 3;'],
      ["package-lock.json", '{"lockfileVersion":3,"version":"changed"}'],
      ["wrangler.jsonc", '{"compatibility_date":"2026-09-01"}'],
      ["migrations/0002.sql", 'ALTER TABLE runs ADD hidden INTEGER;'],
    ]) {
      if (file === "src/aim.ts") fixture.write("src/bound.ts", 'export const bound = 2;');
      fixture.write(file, contents);
      const current = await replayInputs(fixture.service);
      assert.notEqual(current.verification, previous.verification, file);
      assert.notEqual(current.grounds, previous.grounds, file);
      previous = current;
    }
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

test("ground rendering and referenced art invalidate grounds; missing or unsafe art never produces an identity", async () => {
  const fixture = replayFixture();
  try {
    let previous = await replayInputs(fixture.service);
    for (const [file, contents] of [["src/ground.ts", 'export const paint = () => 2; export const groundKey = (id) => `runs/${id}.jpg`;'], ["dist/ui/particles.png", "different pixels"], ["scripts/grounds.mjs", "new upload policy"]]) {
      fixture.write(file, contents);
      const current = await replayInputs(fixture.service);
      assert.equal(current.verification, previous.verification);
      assert.notEqual(current.grounds, previous.grounds);
      previous = current;
    }
    fixture.write("src/ground-art.json", '{"terrain":["ter0.png"],"particles":"particles.png","bodyset":"bodyset.png","extra":"new.png"}');
    await assert.rejects(replayInputs(fixture.service), /ENOENT/);
    fixture.write("dist/ui/new.png", "new art");
    previous = await replayInputs(fixture.service);
    fixture.write("dist/ui/new.png", "changed new art");
    assert.notEqual((await replayInputs(fixture.service)).grounds, previous.grounds);
    fixture.write("src/ground-art.json", '{"terrain":["../outside.png"]}');
    await assert.rejects(replayInputs(fixture.service), /Invalid ground art path/);
  } finally { rmSync(fixture.directory, { recursive: true, force: true }); }
});

const replayIdentities = { schema: 1, verification: "1".repeat(64), grounds: "2".repeat(64) };
const replayBaseline = { sha, inputs: replayIdentities, completed: true };

test("reuses only completed identities for the live commit; any missing or malformed baseline falls back to full work", () => {
  const reuse = replayPlan(replayIdentities, replayBaseline, sha);
  assert.equal(reuse.reverify, false);
  assert.equal(reuse.grounds, false);
  assert.equal(reuse.baseline_sha, sha);
  const fallback = [null, {}, { ...replayBaseline, completed: false }, { sha, inputs: replayIdentities }, { ...replayBaseline, sha: "b".repeat(40) },
    { ...replayBaseline, inputs: { ...replayIdentities, schema: 2 } },
    { ...replayBaseline, inputs: { ...replayIdentities, grounds: "bad" } },
    { ...replayBaseline, inputs: { ...replayIdentities, unknown: true } }];
  for (const baseline of fallback) {
    const plan = replayPlan(replayIdentities, baseline, sha);
    assert.equal(plan.reverify, true);
    assert.equal(plan.grounds, true);
    assert.equal(plan.baseline_sha, null);
  }
  assert.equal(replayPlan(replayIdentities, replayBaseline, null).reverify, true);
  assert.equal(replayPlan(replayIdentities, replayBaseline, sha, true).reverify, true);
  for (const key of ["verification", "grounds"])
    assert.equal(replayPlan({ ...replayIdentities, [key]: "3".repeat(64) }, replayBaseline, sha).reverify, true);
});

test("the reuse gate rejects changed production, altered plans and failed marker requests before deployment", async () => {
  const plan = { sha: "b".repeat(40), ...replayPlan(replayIdentities, replayBaseline, sha) };
  const same = async () => new Response(sha);
  await checkReplayPlan(plan, replayIdentities, plan.sha, same);
  await assert.rejects(checkReplayPlan(plan, replayIdentities, plan.sha, async () => new Response("c".repeat(40))), /Production changed/);
  await assert.rejects(checkReplayPlan(plan, replayIdentities, sha, same), /another release/);
  await assert.rejects(checkReplayPlan(plan, { ...replayIdentities, grounds: "3".repeat(64) }, plan.sha, same), /inputs changed/);
  await assert.rejects(checkReplayPlan({ ...plan, grounds: true }, replayIdentities, plan.sha, same), /Incomplete/);
  for (const response of [new Response("old html"), new Response(sha, { status: 503 })])
    await assert.rejects(productionSha(async () => response));
  await assert.rejects(checkReplayPlan(plan, replayIdentities, plan.sha, async () => { throw Error("network failed"); }), /network failed/);
  const full = { sha: plan.sha, ...replayPlan(replayIdentities, null, null) };
  await checkReplayPlan(full, replayIdentities, full.sha, async () => { throw Error("full verification needs no baseline"); });
});

test("completion recording is bound to the live revision and propagates storage failure", async () => {
  const recorded = [];
  await recordReplayBaseline(replayIdentities, sha, async (value) => recorded.push(value), async () => new Response(sha));
  assert.deepEqual(recorded, [replayBaseline]);
  await assert.rejects(recordReplayBaseline(replayIdentities, sha, async () => assert.fail("must not write"), async () => new Response("b".repeat(40))), /Production changed/);
  await assert.rejects(recordReplayBaseline(replayIdentities, sha, async () => { throw Error("R2 write failed"); }, async () => new Response(sha)), /R2 write failed/);
});


test("a failed full attempt invalidates prior completion, including a forced audit of the live commit", async () => {
  let baseline = replayBaseline;
  const put = async (value) => { baseline = value; };
  const reuse = { sha, ...replayPlan(replayIdentities, baseline, sha) };
  await beginReplayWork(reuse, async () => assert.fail("reuse must not invalidate its baseline"));
  const full = { sha, ...replayPlan(replayIdentities, baseline, sha, true) };
  await beginReplayWork(full, put);
  assert.equal(baseline.completed, false);
  // If verification, upload or smoke fails, recordReplayBaseline is never reached by the workflow.
  assert.equal(replayPlan(replayIdentities, baseline, sha).reverify, true);
  await recordReplayBaseline(replayIdentities, sha, put, async () => new Response(sha));
  assert.equal(replayPlan(replayIdentities, baseline, sha).reverify, false);
  await assert.rejects(beginReplayWork(full, async () => { throw Error("R2 permission denied"); }), /R2 permission denied/);
});
