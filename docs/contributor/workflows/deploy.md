---
tags:
  - contributor
  - workflows
---

# Deploy crimson.land

The **Deploy crimson.land** Actions workflow is manually triggered from
`master`. It assembles the Worker, site and browser game using a successful
**Crimson runtime** build of the exact same commit. PR artifacts and builds of
other commits cannot be promoted. Every check it requires (`REQUIRED_CHECKS` in `service/scripts/deploy-preflight.mjs`) must be green.

## Credentials

Create a dedicated token at [Cloudflare API tokens](https://dash.cloudflare.com/profile/api-tokens).
Use a custom token with these permissions, scoped to the account that owns
the `crimson-land` Worker and the `crimson.land` zone:

| Resource | Permission | Purpose |
| --- | --- | --- |
| Account | Workers Scripts: Edit | Publish the Worker and its static assets |
| Account | D1: Read | Check applied migrations and select active runs |
| Account | Workers R2 Storage: Edit | Download stored replays and upload baked run grounds |
| Zone | Zone: Read | Resolve the site's zone |
| Zone | Workers Routes: Edit | Keep the configured custom domain attached |

The workflow never applies migrations or changes leaderboard data. D1 queries
accept read permissions. After deploying, it writes the grounds baked during
reverification to R2 and removes grounds for runs deleted during the upload.
Wrangler's R2 object-write API requires Workers R2 Storage: Edit. The token
still grants production code deployment, so give it an expiry and rotate it
when needed. Account permission scopes may cover other Workers or storage in
that account; do not use a global API key.

Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` to the repository's
[Actions secrets](https://github.com/banteg/crimson/settings/secrets/actions).
The account ID is shown on the Cloudflare account overview. Existing Worker
OAuth secrets remain in Cloudflare; deployments do not delete them.

Configure a `production` [GitHub environment](https://github.com/banteg/crimson/settings/environments)
with deployment branches limited to `master`. A required reviewer is optional
for this manually triggered workflow. Environment secrets can replace the
repository secrets if credentials should be available only to production jobs.

## Run a deployment

1. Wait for all required checks on the current `master` commit to pass.
2. Open [Deploy crimson.land](https://github.com/banteg/crimson/actions/workflows/deploy.yml)
   and choose **Run workflow**, branch `master`. Leave the runtime run ID empty
   to select a successful complete runtime run automatically.
3. Keep **dry_run** checked for a rehearsal. It packages and checks the whole
   release without Cloudflare credentials or production access.
4. To publish, run again with **dry_run** unchecked. The production job checks
   the package hashes, requires all migrations already applied, and reverifies
   every active production run before uploading. It checks master and required
   checks again immediately before upload.

Normal push CI keeps its path filters, so service-only, client-only, site and
documentation commits may omit a deployment artifact. With no runtime run ID
specified, the deployment preflight requests a **release-only** Crimson
runtime run when no suitable build exists. It builds the verifier, game module
and web package for this master commit, without repeating corpus, parity,
oracles or desktop builds. Existing required checks must already be green;
checks and master are rechecked after the artifact build and before upload.

Compiler/package cache keys use content identities: unchanged game inputs
reuse the module across commits; unchanged client inputs and module bytes reuse
the web package. Manifests retain the original build commit and artifact hashes
when reused. The release manifest separately identifies the commit being deployed.
A source or toolchain change invalidates the affected build; a first cold
preparation can still take a few minutes.

A fingerprint names build inputs, not replay compatibility or permission to
promote an old workflow run. The full SHA-256 is in each build manifest; replay
labels display its first 24 hex characters. The shared input inventory lives in
`scripts/build_identity.py`, and compiler flags are covered by the build-script
hashes. Keep that inventory and its invalidation tests current when adding inputs.

A trusted runtime run for the deployment commit can restore an unchanged module
or client from a prior build, verify its identity and bytes, and upload it as an
artifact of the current run. Its manifest keeps the original build commit. The
deployment preflight still refuses runs of another commit and requires all green
checks; a fingerprint never substitutes for runtime validation or replay checks.
Job reruns can retain older artifacts with the same name; the preflight
validates the newest ID per name and pins exact downloads in the manifest.

An explicitly supplied runtime run ID must already contain valid artifacts;
it never falls back to another build. Expired artifacts can be rebuilt with
**Crimson runtime** on `master`, with **release_only** checked. Leave that
option unchecked for the complete validation suite. Release-only builds
from other branches or a master commit whose required checks are not already
green fail explicitly. The release-only compilation and its
logs are retained in the selected runtime workflow run.

Production jobs are serialized and are not automatically cancelled during upload.
Dry runs prepare releases independently and cannot replace a pending production job.
By default, GitHub keeps one pending production job; a newer production request
replaces an older pending request.
An older request is rejected if master advanced while it waited. A master
change after the last check is still possible; the release always remains
pinned to the recorded commit.

## Migrations and replay changes

The workflow fails if a local migration is not applied, or production lists a
migration absent from the selected commit. Review and apply migrations
separately with Wrangler before retrying. An untracked production schema
change is not detected by comparing migration names.

`service/scripts/reverify.mjs` reads the current active run IDs from production
D1 each time and downloads missing replays from R2 with at most four concurrent
requests into a local cache. Only complete downloads are reused. Download and verification timings are logged.
The local cache is not uploaded to Actions caches: active runs include hidden
and banned runs that the public replay route refuses, and fork PRs can read
default-branch Actions caches. Every active replay is verified against this
release's WASM and TypeScript verifier on every deployment. A matching WASM
hash alone cannot bypass changes in the TypeScript verifier. A failed run
blocks upload and reports possible retirement SQL; the workflow does not
execute that SQL. Follow the [ranked rules](../../rewrite/ranked-rules.md#when-the-verifier-changes)
to decide whether to fix the verifier or retire affected runs.

Reverification covers the run list at its start. Uploads may continue while
the check runs; this does not create an atomic release transaction over D1,
R2 and the Worker. Large or incompatible rule changes need a coordinated
release window.

After the Worker deploys, `npm run grounds` uploads each verified run's baked
ground to `crimson-land-replays/runs/<id>.ground.jpg`. This avoids a cold
reverification when a visitor or card crawler first requests an older run.
An R2 authentication failure here leaves the new Worker live but stops the
workflow before its smoke check. Change the deployment token's Workers R2
Storage permission from Read to Edit, then rerun the failed deploy job: it
reverifies and bakes the grounds again because the previous runner's files
were temporary. The rerun still requires the deployment commit to be current
master with green checks; if master advanced, start a new deployment instead.

## Evidence and rollback

The `crimson-land-release` artifact contains the prepared release tarball and
`release.json`: deployment commit, runtime run, selected artifact IDs, original
verifier/game/client build provenance and SHA-256 hashes of the Worker modules,
site files, verifier and Wrangler config. The deployment summary and
`crimson-land-deployment` artifact retain Wrangler output, including the
Cloudflare version ID. The `/deployment.txt` the workflow generates identifies
the published commit. The smoke check polls it for up to 60 seconds to allow propagation and
rejects a different revision before checking assets. Production smoke checks
cover the site, leaderboard
API, game page, JS/WASM and availability of all three game archives.

A smoke-check failure marks the workflow failed after deployment; it does not
automatically revert production. Review the failure, then use
`npx wrangler rollback <version-id>` from `service/` or the Cloudflare
Deployments page to restore the chosen version. Worker rollback does not undo
D1 migrations or R2 changes. Keep schema changes compatible with the previous
Worker where a code rollback is intended.

Local deployment remains available through `npm --prefix service run deploy`. It
rebuilds the site assets and the browser game, so it needs the game art and the
client toolchain (wasi-sdk, wabt, Emscripten). Build the verifier first with
`uv run python crimson-core/build.py --target wasm`, and run
`node scripts/deploy-checks.mjs migrations` and `npm run reverify` from `service/`
before publishing. A local deploy writes no `/deployment.txt`.

## Game archives

The game archives are not part of a deploy. `/play/game/<name>.paq` serves
`v1.9.93/<name>.paq` from the `crimson` R2 bucket, the same objects the asset host
publishes for the Python game and the desktop client. Replace them separately,
after deploying any client change they depend on; the smoke check only confirms
they are reachable.
