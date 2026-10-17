// Skips reverification and ground uploads when the code that verifies and bakes replays is unchanged since the live
// deployment. The identity covers what actually runs, not a path filter: the bundled entry points with every
// transitive module, the WASM bytes they load, the ground art, the runner scripts and the locked dependencies they run
// on. The Worker's config and migrations stay out: reverify runs in Node and only reads production's runs.
//
// CI replays the ranked runs under the same identity before a deploy (reverify.mjs --public) and publishes the
// verdicts as the artifact replay-verdicts-<identity>; a deploy with no live record to reuse takes those and verifies
// only the runs CI did not see.
//
//   node scripts/deploy-replays.mjs inputs     print this checkout's identity (the `inputs` output)
//   node scripts/deploy-replays.mjs verdicts   find a trusted master run's verdicts for it (the `verdicts_*` outputs)
//   node scripts/deploy-replays.mjs plan       reuse the live deployment's checks, take CI's verdicts (VERDICTS, their
//                                              directory) or verify everything: the `reverify` and `mode` outputs
//   node scripts/deploy-replays.mjs record     after a successful deploy, record this commit's identity
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { api, pages, requireMasterRun } from "./deploy-preflight.mjs";
import { r2Bucket } from "./r2.mjs";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const PLAN = join(SERVICE, "../deployment-plan.json");
const RECORD = "deploy/replay-inputs.json";
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
    dependencies: file("package-lock.json"),
  }));
}

// Reuse only a record of the commit production still serves: a failed or rolled-back deploy never matches it. Else take
// CI's verdicts for these same inputs (`verdicts`, theirs), or verify everything.
export function replayPlan(inputs, record, liveSha, { force = false, verdicts = null } = {}) {
  const reuse = !force && record?.inputs === inputs && record.sha === liveSha;
  const mode = reuse ? "reuse" : !force && verdicts === inputs ? "delta" : "full";
  return { inputs, reuse: reuse ? record.sha : null, reverify: !reuse, mode };
}

export const verdictsArtifact = (inputs) => `replay-verdicts-${inputs}`;

// The newest unexpired verdicts for `inputs` that a trusted master run published, whichever commit it ran on: the
// identity is what they depend on. A PR's run, or a fork's, never counts.
export async function findVerdicts(inputs, repository, request = api) {
  const artifacts = await pages(`actions/artifacts?name=${verdictsArtifact(inputs)}`, "artifacts", request);
  for (const artifact of artifacts.filter(({ expired }) => !expired).sort((a, b) => b.id - a.id)) {
    const run = await request(`actions/runs/${artifact.workflow_run.id}`);
    try {
      requireMasterRun(run, repository);
    } catch {
      continue;
    }
    return { run_id: run.id, artifact_id: artifact.id };
  }
  return null;
}

const output = (line) => process.env.GITHUB_OUTPUT && appendFileSync(process.env.GITHUB_OUTPUT, `${line}\n`);
const summary = (line) => process.env.GITHUB_STEP_SUMMARY && appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`);

async function productionSha() {
  try {
    const response = await fetch("https://crimson.land/deployment.txt", { headers: { "Cache-Control": "no-cache" }, signal: AbortSignal.timeout(15000) });
    return response.ok ? (await response.text()).trim() : null;
  } catch { return null; }
}

async function main() {
  switch (process.argv[2]) {
    case "inputs": {
      const inputs = await replayInputs();
      console.log(inputs);
      return output(`inputs=${inputs}`);
    }
    case "verdicts": {
      const inputs = await replayInputs();
      const found = await findVerdicts(inputs, process.env.GITHUB_REPOSITORY);
      const message = found
        ? `CI's replay verdicts for these inputs: artifact ${found.artifact_id} of run ${found.run_id}.`
        : "No CI replay verdicts for these inputs: a reverify would replay every active run.";
      console.log(message);
      summary(message);
      if (found) output(`verdicts_run_id=${found.run_id}\nverdicts_artifact_id=${found.artifact_id}`);
      return;
    }
    case "plan": {
      const inputs = await replayInputs();
      const record = await r2Bucket().get(RECORD).then((bytes) => JSON.parse(new TextDecoder().decode(bytes)), () => null);
      const verdicts = process.env.VERDICTS && join(process.env.VERDICTS, "verdicts.json");
      const plan = replayPlan(inputs, record, await productionSha(), {
        force: process.env.FORCE_REVERIFY === "true",
        verdicts: verdicts && existsSync(verdicts) ? JSON.parse(readFileSync(verdicts, "utf8")).inputs : null,
      });
      writeFileSync(PLAN, `${JSON.stringify(plan, null, 2)}\n`);
      const message = {
        reuse: `Replay inputs unchanged since ${plan.reuse}: reuse its verification and grounds.`,
        delta: "Take CI's verdicts for these replay inputs and verify only the active runs CI did not see.",
        full: "Reverify and bake all active runs: inputs changed with no CI verdicts for them, no record of the live deployment, or forced.",
      }[plan.mode];
      console.log(message);
      output(`reverify=${plan.reverify}\nmode=${plan.mode}`);
      summary(message);
      return;
    }
    case "record": {
      const { inputs } = JSON.parse(readFileSync(PLAN, "utf8"));
      return r2Bucket().put(RECORD, `${JSON.stringify({ sha: process.env.GITHUB_SHA, inputs })}\n`, "application/json");
    }
    default: throw Error("Expected plan or record");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
