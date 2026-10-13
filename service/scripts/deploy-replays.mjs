// Skips reverification and ground uploads when the code that verifies and bakes replays is unchanged since the live
// deployment. The identity covers what actually runs, not a path filter: the bundled entry points with every
// transitive module, the WASM bytes they load, the ground art, the runner scripts, dependencies and Wrangler config.
//
//   node scripts/deploy-replays.mjs plan     compare against the live deployment's record, set the `reverify` output
//   node scripts/deploy-replays.mjs record   after a successful deploy, record this commit's identity
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const PLAN = join(SERVICE, "../deployment-plan.json");
const RECORD = "crimson-land-replays/deploy/replay-inputs.json";
const execFileAsync = promisify(execFile);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

export async function replayInputs(service = SERVICE) {
  service = realpathSync(service);
  const file = (path) => digest(readFileSync(join(service, path)));
  const { build } = await import("esbuild");
  // WASM imports become placeholders in the bundle; their real bytes enter the identity separately.
  const wasm = {};
  const result = await build({
    stdin: {
      contents: [
        'export { verifyRun } from "./src/verify";',
        'export { decodeReplay, inflateReplay, REPLAY_RULES } from "./src/replay";',
        'export { encodeTransport } from "./src/transport";',
        'export { unrankedReasons, outcomeReasons, rankedBoard, rankedScore } from "./src/ranked";',
        'export { verifyWithGround } from "./src/runs";',
        'export { groundKey } from "./src/ground";',
      ].join("\n"),
      resolveDir: service, sourcefile: "replay-identity.ts", loader: "ts",
    },
    absWorkingDir: service,
    bundle: true, write: false, format: "esm", platform: "browser", target: "es2024",
    minifyWhitespace: true, legalComments: "none", logLevel: "silent",
    plugins: [{ name: "wasm-identity", setup(builder) {
      builder.onLoad({ filter: /\.wasm$/ }, ({ path }) => {
        wasm[relative(service, path)] = digest(readFileSync(path));
        return { contents: "export default null;", loader: "js" };
      });
    } }],
  });
  const art = JSON.parse(readFileSync(join(service, "src/ground-art.json"), "utf8"));
  return digest(JSON.stringify({
    code: digest(result.outputFiles[0].text),
    wasm: Object.entries(wasm).sort(),
    art: Object.values(art).flat().sort().map((name) => [name, file(join("dist/ui", name))]),
    scripts: ["deploy-replays", "reverify", "reverify-pool", "reverify-worker", "grounds"].map((name) => file(`scripts/${name}.mjs`)),
    dependencies: ["package.json", "package-lock.json", "wrangler.jsonc"].map(file),
    migrations: readdirSync(join(service, "migrations")).sort().map((name) => [name, file(join("migrations", name))]),
  }));
}

// Reuse only a record of the commit production still serves: a failed or rolled-back deploy never matches it.
export function replayPlan(inputs, record, liveSha, force = false) {
  const reuse = !force && record?.inputs === inputs && record.sha === liveSha;
  return { inputs, reuse: reuse ? record.sha : null, reverify: !reuse };
}

async function productionSha() {
  try {
    const response = await fetch("https://crimson.land/deployment.txt", { headers: { "Cache-Control": "no-cache" }, signal: AbortSignal.timeout(15000) });
    return response.ok ? (await response.text()).trim() : null;
  } catch { return null; }
}

const wrangler = (...args) =>
  execFileAsync("npx", ["--no-install", "wrangler", ...args, "--remote", "--config", join(SERVICE, "wrangler.jsonc")], { cwd: SERVICE });

async function withTemporary(work) {
  const directory = mkdtempSync(join(tmpdir(), "crimson-replay-record-"));
  try { return await work(join(directory, "record.json")); } finally { rmSync(directory, { recursive: true, force: true }); }
}

async function main() {
  switch (process.argv[2]) {
    case "plan": {
      const inputs = await replayInputs();
      const record = await withTemporary(async (path) => {
        try {
          await wrangler("r2", "object", "get", RECORD, "--file", path);
          return JSON.parse(readFileSync(path, "utf8"));
        } catch { return null; }
      });
      const plan = replayPlan(inputs, record, await productionSha(), process.env.FORCE_REVERIFY === "true");
      writeFileSync(PLAN, `${JSON.stringify(plan, null, 2)}\n`);
      const message = plan.reuse
        ? `Replay inputs unchanged since ${plan.reuse}: reuse its verification and grounds.`
        : "Reverify and bake all active runs: inputs changed, no record of the live deployment, or forced.";
      console.log(message);
      if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `reverify=${plan.reverify}\n`);
      if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${message}\n`);
      return;
    }
    case "record": {
      const { inputs } = JSON.parse(readFileSync(PLAN, "utf8"));
      return withTemporary(async (path) => {
        writeFileSync(path, `${JSON.stringify({ sha: process.env.GITHUB_SHA, inputs })}\n`);
        await wrangler("r2", "object", "put", RECORD, "--file", path, "--content-type", "application/json");
      });
    }
    default: throw Error("Expected plan or record");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
