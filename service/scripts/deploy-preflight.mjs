import assert from "node:assert/strict";
import { appendFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const REQUIRED_CHECKS = [
  "ast-grep", "build", "client-gate", "core-gate", "decomp-gate", "docs-check",
  "match-regressions", "native-closure", "native-oracle", "pytest", "resolved-name-audit",
  "ruff", "service-gate", "ty",
];

export function requireGreenChecks(checks) {
  const latest = new Map();
  for (const check of checks) {
    if (check.app?.slug !== "github-actions") continue;
    if (!latest.has(check.name) || check.id > latest.get(check.name).id) latest.set(check.name, check);
  }
  const failed = REQUIRED_CHECKS.filter((name) => {
    const check = latest.get(name);
    return check?.status !== "completed" || check.conclusion !== "success";
  });
  assert.equal(failed.length, 0, `Required checks are missing, unfinished or unsuccessful: ${failed.join(", ")}`);
}

export function requireTrustedRun(run, repository, sha) {
  assert.equal(run.head_repository?.full_name, repository, "Build must belong to this repository");
  assert.equal(run.head_branch, "master", "Build must be from master");
  assert.equal(run.head_sha, sha, "Build must match the deployment commit");
  assert.equal(run.path, ".github/workflows/core.yml", "Build must use the runtime workflow");
  assert.ok(["push", "workflow_dispatch"].includes(run.event), "PR builds cannot be deployed");
  assert.equal(run.status, "completed", "Build is unfinished");
  assert.equal(run.conclusion, "success", "Build was unsuccessful");
}

export function requireArtifacts(artifacts, sha) {
  for (const name of ["runtime-wasm", "crimsonland-web"]) {
    const matches = artifacts.filter((artifact) => artifact.name === name && !artifact.expired);
    assert.equal(matches.length, 1, `Need one unexpired ${name} artifact; run Crimson runtime manually on master first`);
    assert.equal(matches[0].workflow_run?.head_sha, sha, `Wrong commit in ${name}`);
    assert.ok(matches[0].size_in_bytes > 0, `Empty ${name} artifact`);
  }
}

async function api(path) {
  const response = await fetch(`https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/${path}`, {
    headers: { Authorization: `Bearer ${process.env.GH_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
    signal: AbortSignal.timeout(30000),
  });
  assert.ok(response.ok, `GitHub ${path}: HTTP ${response.status}`);
  return response.json();
}

async function pages(path, key) {
  const rows = [];
  for (let page = 1; ; page++) {
    const data = await api(`${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    rows.push(...data[key]);
    if (data[key].length < 100) return rows;
  }
}

async function main() {
  const sha = process.env.GITHUB_SHA;
  const repository = process.env.GITHUB_REPOSITORY;
  assert.equal(process.env.GITHUB_REF, "refs/heads/master", "Run deployment from master");
  assert.match(sha, /^[a-f0-9]{40}$/);
  assert.equal((await api("branches/master")).commit.sha, sha, "Deployment is superseded by a newer master commit");
  requireGreenChecks(await pages(`commits/${sha}/check-runs?filter=all`, "check_runs"));
  if (process.argv.includes("--checks-only")) return;

  const requested = process.env.RUNTIME_RUN_ID;
  if (requested) assert.match(requested, /^\d+$/, "Runtime run ID must be numeric");
  const candidates = requested
    ? [await api(`actions/runs/${requested}`)]
    : await pages(`actions/workflows/core.yml/runs?branch=master&head_sha=${sha}&status=success`, "workflow_runs");
  for (const run of candidates) {
    try {
      requireTrustedRun(run, repository, sha);
      requireArtifacts(await pages(`actions/runs/${run.id}/artifacts`, "artifacts"), sha);
    } catch (error) {
      if (requested) throw error;
      console.log(`Skipping runtime run ${run.id}: ${error.message}`);
      continue;
    }
    const release = { sha, runtime_run_id: run.id, runtime_run_attempt: run.run_attempt, runtime_url: run.html_url };
    writeFileSync("release.json", `${JSON.stringify(release, null, 2)}\n`);
    appendFileSync(process.env.GITHUB_OUTPUT, `runtime_run_id=${run.id}\n`);
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `Deploying \`${sha}\` from [runtime run ${run.id}](${run.html_url}).\n`);
    return;
  }
  throw Error("No complete successful runtime build for this master commit. Run Crimson runtime manually on master, then retry deployment.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
