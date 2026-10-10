import assert from "node:assert/strict";
import { appendFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

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
  const selected = {};
  for (const name of ["runtime-wasm", "crimsonland-web"]) {
    const matches = artifacts.filter((artifact) => artifact.name === name);
    assert.ok(matches.length > 0, `Missing ${name} artifact; run Crimson runtime manually on master first`);
    for (const artifact of matches) assert.ok(Number.isSafeInteger(artifact.id) && artifact.id > 0, `Invalid ${name} artifact ID`);
    // Job reruns retain earlier artifacts with the same name. Pin the newest ID rather than rely on name lookup.
    const latest = matches.reduce((a, b) => a.id > b.id ? a : b);
    assert.equal(latest.expired, false, `Expired ${name} artifact; run Crimson runtime manually on master first`);
    assert.equal(latest.workflow_run?.head_sha, sha, `Wrong commit in ${name}`);
    assert.ok(latest.size_in_bytes > 0, `Empty ${name} artifact`);
    selected[name] = latest.id;
  }
  return selected;
}

async function api(path, options = {}) {
  const response = await fetch(`https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/${path}`, {
    headers: { Authorization: `Bearer ${process.env.GH_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
    signal: AbortSignal.timeout(30000),
    ...options,
  });
  assert.ok(response.ok, `GitHub ${path}: HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}

async function pages(path, key, request = api) {
  const rows = [];
  for (let page = 1; ; page++) {
    const data = await request(`${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    rows.push(...data[key]);
    if (data[key].length < 100) return rows;
  }
}

// Normal push CI can omit either artifact. Request only their producers, after master checks are green.
export async function resolveRuntimeBuild(repository, sha, requested = "", {
  request = api, pause = delay, now = Date.now, timeoutMs = 600000, intervalMs = 10000,
} = {}) {
  const find = async () => {
    const candidates = requested
      ? [await request(`actions/runs/${requested}`)]
      : await pages(`actions/workflows/core.yml/runs?branch=master&head_sha=${sha}&status=success`, "workflow_runs", request);
    for (const run of candidates) {
      try {
        requireTrustedRun(run, repository, sha);
      } catch (error) {
        if (requested) throw error;
        continue;
      }
      const rows = await pages(`actions/runs/${run.id}/artifacts`, "artifacts", request);
      try {
        const artifacts = requireArtifacts(rows, sha);
        return { sha, runtime_run_id: run.id, runtime_run_attempt: run.run_attempt, runtime_url: run.html_url, artifacts };
      } catch (error) {
        if (requested) throw error;
      }
    }
  };
  if (requested) assert.match(requested, /^\d+$/, "Runtime run ID must be numeric");
  const existing = await find();
  if (existing) return existing;
  if (requested) throw Error("Requested runtime run does not contain valid deployment artifacts");
  const current = async () => assert.equal((await request("branches/master")).commit.sha, sha, "Deployment is superseded by a newer master commit");
  await current();
  console.log("Requesting same-commit release-only runtime build (no corpus, parity, oracles or desktop builds)");
  await request("actions/workflows/core.yml/dispatches", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.GH_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" },
    body: JSON.stringify({ ref: "master", inputs: { release_only: true } }),
  });
  const deadline = now() + timeoutMs;
  while (now() < deadline) {
    await pause(Math.min(intervalMs, deadline - now()));
    await current();
    const release = await find();
    if (release) return release;
  }
  throw Error("Timed out waiting for release-only runtime artifacts; inspect Crimson runtime on master");
}

async function main() {
  const sha = process.env.GITHUB_SHA;
  const repository = process.env.GITHUB_REPOSITORY;
  assert.equal(process.env.GITHUB_REF, "refs/heads/master", "Run deployment from master");
  assert.match(sha, /^[a-f0-9]{40}$/);
  assert.equal((await api("branches/master")).commit.sha, sha, "Deployment is superseded by a newer master commit");
  requireGreenChecks(await pages(`commits/${sha}/check-runs?filter=all`, "check_runs"));
  if (process.argv.includes("--checks-only")) return;

  const release = await resolveRuntimeBuild(repository, sha, process.env.RUNTIME_RUN_ID || "");
  // A dispatch produces new gate checks; require their completion and recheck master before packaging.
  assert.equal((await api("branches/master")).commit.sha, sha, "Deployment is superseded by a newer master commit");
  requireGreenChecks(await pages(`commits/${sha}/check-runs?filter=all`, "check_runs"));
  writeFileSync("release.json", `${JSON.stringify(release, null, 2)}\n`);
  appendFileSync(process.env.GITHUB_OUTPUT, `runtime_run_id=${release.runtime_run_id}\nwasm_artifact_id=${release.artifacts["runtime-wasm"]}\nweb_artifact_id=${release.artifacts["crimsonland-web"]}\n`);
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `Deploying \`${sha}\` from [runtime run ${release.runtime_run_id}](${release.runtime_url}).\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
