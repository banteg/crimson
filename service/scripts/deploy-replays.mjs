// Content identities for replay verification and its baked grounds. Completion is recorded only after a successful
// production smoke check, and reused only while /deployment.txt still names that deployment.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { appendFileSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const INPUTS = "release-worker/replay-inputs.json";
const BASELINE = "crimson-land-replays/deploy/replay-inputs.json";
const ORIGIN = "https://crimson.land";
const execFileAsync = promisify(execFile);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
  : JSON.stringify(value);

export function requireReplayInputs(inputs) {
  assert.ok(inputs && typeof inputs === "object", "Missing replay input identities");
  assert.deepEqual(Object.keys(inputs).sort(), ["grounds", "schema", "verification"], "Unknown replay identity fields");
  assert.equal(inputs.schema, 1, "Unknown replay identity schema");
  for (const key of ["verification", "grounds"]) assert.match(inputs[key], /^[a-f0-9]{64}$/, `Invalid ${key} identity`);
  return inputs;
}

// Bundle the actual entry points, including their transitive TypeScript/JSON/package dependencies. WASM imports
// are placeholders here, never executed; their real bytes enter the identity separately. Tree shaking keeps
// ground rendering out of the verification identity when verify.ts imports only the bake-buffer size.
export async function replayInputs(service = SERVICE) {
  service = realpathSync(service);
  const { build } = await import("esbuild");
  const { parse } = await import("jsonc-parser");
  const errors = [];
  const config = parse(readFileSync(join(service, "wrangler.jsonc"), "utf8"), errors, { allowTrailingComma: true });
  assert.equal(errors.length, 0, "Invalid Wrangler configuration");
  const migrations = Object.fromEntries(readdirSync(join(service, "migrations")).filter((file) => file.endsWith(".sql")).sort()
    .map((file) => [file, digest(readFileSync(join(service, "migrations", file)))]));
  const common = {
    schema: 1,
    recipe: {
      planner: digest(readFileSync(fileURLToPath(import.meta.url))),
      runner: digest(readFileSync(join(service, "scripts/reverify.mjs"))),
      package: digest(readFileSync(join(service, "package.json"))),
    },
    dependencies: digest(readFileSync(join(service, "package-lock.json"))),
    config,
    migrations,
  };
  async function bundle(contents) {
    const wasm = new Map();
    const result = await build({
      stdin: { contents, resolveDir: service, sourcefile: "replay-identity.ts", loader: "ts" },
      absWorkingDir: service,
      bundle: true, write: false, format: "esm", platform: "browser", target: "es2024",
      treeShaking: true, minifyWhitespace: true, legalComments: "none", logLevel: "silent",
      plugins: [{ name: "wasm-identity", setup(builder) {
        builder.onLoad({ filter: /\.wasm$/ }, ({ path }) => {
          wasm.set(relative(service, path).replaceAll("\\", "/"), digest(readFileSync(path)));
          return { contents: "export default null;", loader: "js" };
        });
      } }],
    });
    return { code: result.outputFiles[0].text, wasm: Object.fromEntries([...wasm].sort(([a], [b]) => a.localeCompare(b))) };
  }
  const verification = digest(canonical({ ...common, ...await bundle([
    'export { verifyRun } from "./src/verify";',
    'export { decodeReplay, inflateReplay, REPLAY_RULES } from "./src/replay";',
    'export { encodeTransport } from "./src/transport";',
    'export { unrankedReasons, outcomeReasons, rankedBoard, rankedScore } from "./src/ranked";',
  ].join("\n")) }));
  // The renderer and planner share this inventory so a newly referenced texture cannot be omitted from its hash.
  const art = JSON.parse(readFileSync(join(service, "src/ground-art.json"), "utf8"));
  const imagesOf = (value) => Array.isArray(value) ? value.flatMap(imagesOf)
    : value && typeof value === "object" ? Object.values(value).flatMap(imagesOf) : [value];
  const images = imagesOf(art);
  const assets = Object.fromEntries(images.sort().map((file) => {
    assert.ok(typeof file === "string" && file && !file.includes("/") && !file.includes("\\") && file !== "." && file !== "..", "Invalid ground art path");
    return [file, digest(readFileSync(join(service, "dist/ui", file)))];
  }));
  const grounds = digest(canonical({ ...common, verification, assets,
    upload: digest(readFileSync(join(service, "scripts/grounds.mjs"))),
    ...await bundle('export { verifyWithGround } from "./src/runs"; export { groundKey } from "./src/ground";'),
  }));
  return requireReplayInputs({ schema: 1, verification, grounds });
}

// A missing, malformed, older-format or mismatched baseline always requires the full work. Ground regeneration
// also simulates the runs, so it uses reverify.mjs even when only the rendering identity changed.
export function replayPlan(inputs, baseline, liveSha, force = false) {
  requireReplayInputs(inputs);
  let trusted = false;
  try {
    requireReplayInputs(baseline.inputs);
    assert.equal(baseline.completed, true, "Replay work did not complete");
    assert.match(baseline.sha, /^[a-f0-9]{40}$/);
    trusted = baseline.sha === liveSha;
  } catch { /* No usable successful deployment baseline. */ }
  const verificationChanged = !trusted || inputs.verification !== baseline.inputs.verification;
  const groundsChanged = !trusted || inputs.grounds !== baseline.inputs.grounds;
  return {
    inputs, baseline_sha: trusted ? liveSha : null,
    verification_changed: verificationChanged, grounds_changed: groundsChanged,
    reverify: force || verificationChanged || groundsChanged,
    grounds: force || verificationChanged || groundsChanged,
  };
}

// Invalidate previous completion before a full attempt, including a forced audit of the same commit. Otherwise
// a failed audit could leave the earlier same-commit record reusable. A storage failure blocks the attempt early.
export async function beginReplayWork(plan, put) {
  requireReplayInputs(plan.inputs);
  assert.match(plan.sha, /^[a-f0-9]{40}$/);
  assert.equal(typeof plan.reverify, "boolean", "Invalid replay plan");
  if (plan.reverify) await put({ sha: plan.sha, inputs: plan.inputs, completed: false });
}

export async function productionSha(request = fetch) {
  const response = await request(`${ORIGIN}/deployment.txt`, {
    headers: { "Cache-Control": "no-cache" }, signal: AbortSignal.timeout(15000),
  });
  assert.equal(response.status, 200, "Cannot read the production deployment marker");
  const sha = (await response.text()).trim();
  assert.match(sha, /^[a-f0-9]{40}$/, "Invalid production deployment marker");
  return sha;
}

export async function checkReplayPlan(plan, inputs, sha, request = fetch) {
  requireReplayInputs(inputs);
  assert.equal(plan.sha, sha, "Replay plan belongs to another release");
  assert.deepEqual(plan.inputs, inputs, "Replay inputs changed after planning");
  assert.equal(typeof plan.reverify, "boolean", "Invalid replay plan");
  assert.equal(typeof plan.grounds, "boolean", "Invalid ground plan");
  // The only supported shortcut reuses both completed verification and grounds.
  assert.equal(plan.reverify, plan.grounds, "Incomplete replay plan");
  if (!plan.reverify) {
    assert.match(plan.baseline_sha, /^[a-f0-9]{40}$/, "Missing replay baseline");
    assert.equal(await productionSha(request), plan.baseline_sha, "Production changed after replay planning; retry the deployment");
  }
}

// Commit completion only after the caller's uploads and smoke check passed. Recheck the live revision here too,
// so a concurrent out-of-band deployment never gets credited with this release's identities.
export async function recordReplayBaseline(inputs, sha, put, request = fetch) {
  requireReplayInputs(inputs);
  assert.match(sha, /^[a-f0-9]{40}$/);
  assert.equal(await productionSha(request), sha, "Production changed before recording replay completion");
  await put({ sha, inputs, completed: true });
}

const wrangler = (...args) => execFileAsync("npx", ["--no-install", "wrangler", ...args, "--remote", "--config", join(SERVICE, "wrangler.jsonc")], { cwd: SERVICE });

async function putBaseline(baseline, file) {
  writeFileSync(file, `${JSON.stringify(baseline)}\n`);
  await wrangler("r2", "object", "put", BASELINE, "--file", file, "--content-type", "application/json");
}

function preparedInputs() {
  const release = JSON.parse(readFileSync(join(SERVICE, "../release.json"), "utf8"));
  assert.match(release.sha, /^[a-f0-9]{40}$/);
  if (process.env.GITHUB_SHA) assert.equal(release.sha, process.env.GITHUB_SHA, "Prepared release belongs to another commit");
  const bytes = readFileSync(join(SERVICE, INPUTS));
  assert.equal(digest(bytes), release.files[INPUTS], "Replay identities do not match the prepared package");
  return { sha: release.sha, inputs: requireReplayInputs(JSON.parse(bytes)) };
}

async function main() {
  const command = process.argv[2];
  if (command === "fingerprint") {
    writeFileSync(join(SERVICE, INPUTS), `${JSON.stringify(await replayInputs(), null, 2)}\n`);
    return;
  }
  const { sha, inputs } = preparedInputs();
  if (command === "plan") {
    const temporary = mkdtempSync(join(tmpdir(), "crimson-replay-baseline-"));
    let baseline = null, liveSha = null;
    try {
      try {
        await wrangler("r2", "object", "get", BASELINE, "--file", join(temporary, "baseline.json"));
        baseline = JSON.parse(readFileSync(join(temporary, "baseline.json"), "utf8"));
        liveSha = await productionSha();
      } catch { console.log("No usable live replay baseline; full verification and ground baking required."); }
      const plan = { sha, ...replayPlan(inputs, baseline, liveSha, process.env.FORCE_REVERIFY === "true") };
      writeFileSync(join(SERVICE, "../deployment-plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
      await beginReplayWork(plan, (baseline) => putBaseline(baseline, join(temporary, "baseline.json")));
      const message = plan.reverify
        ? "Reverify and bake all active runs: inputs changed, baseline unavailable, or full verification requested."
        : `Reuse completed verification and grounds from ${plan.baseline_sha}: replay inputs are unchanged.`;
      console.log(message);
      if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `reverify=${plan.reverify}\ngrounds=${plan.grounds}\n`);
      if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${message}\n\n\`\`\`json\n${JSON.stringify(plan, null, 2)}\n\`\`\`\n`);
    } finally { rmSync(temporary, { recursive: true, force: true }); }
    return;
  }
  if (command === "check") {
    await checkReplayPlan(JSON.parse(readFileSync(join(SERVICE, "../deployment-plan.json"), "utf8")), inputs, sha);
    return;
  }
  if (command === "record") {
    const temporary = mkdtempSync(join(tmpdir(), "crimson-replay-baseline-"));
    try {
      await recordReplayBaseline(inputs, sha, (baseline) => putBaseline(baseline, join(temporary, "baseline.json")));
    } finally { rmSync(temporary, { recursive: true, force: true }); }
    return;
  }
  throw Error("Expected fingerprint, plan, check or record");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
