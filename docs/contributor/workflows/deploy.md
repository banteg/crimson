---
tags:
  - contributor
  - workflows
---

# Deploy crimson.land

The **Deploy crimson.land** Actions workflow is manually triggered from
`master`. It assembles the Worker, site and browser game using a successful
**Crimson runtime** build of the exact same commit. PR artifacts and builds of
other commits cannot be promoted. All 14 required checks must be green.

## Credentials

Create a dedicated token at [Cloudflare API tokens](https://dash.cloudflare.com/profile/api-tokens).
Use a custom token with these permissions, scoped to the account that owns
the `crimson-land` Worker and the `crimson.land` zone:

| Resource | Permission | Purpose |
| --- | --- | --- |
| Account | Workers Scripts: Edit | Publish the Worker and its static assets |
| Account | D1: Read | Check applied migrations and select active runs |
| Account | Workers R2 Storage: Read | Download stored replays for reverification |
| Zone | Zone: Read | Resolve the site's zone |
| Zone | Workers Routes: Edit | Keep the configured custom domain attached |

The workflow never applies migrations, changes leaderboard data or writes R2
objects. D1 query and R2 object-read APIs accept read permissions. The token
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

Path-filtered CI may not have produced both the verifier and browser artifacts
on a site-only or documentation-only commit. If the workflow reports missing
artifacts, run **Crimson runtime** manually on `master`, wait for success, then
retry. Manual runtime runs build all targets. Expired artifacts require the
same procedure. No deployment compiler rebuild is hidden in this workflow.

Deployments are serialized and are not automatically cancelled during upload.
An older request is rejected if master advanced while it waited. A master
change after the last check is still possible; the release always remains
pinned to the recorded commit.

## Migrations and replay changes

The workflow fails if a local migration is not applied, or production lists a
migration absent from the selected commit. Review and apply migrations
separately with Wrangler before retrying. An untracked production schema
change is not detected by comparing migration names.

`service/scripts/reverify.mjs` reads the current active run IDs from production
D1 and downloads their replays from R2 into a temporary cache. A failed run
blocks upload and reports possible retirement SQL; the workflow does not
execute that SQL. Follow the [ranked rules](../../rewrite/ranked-rules.md#when-the-verifier-changes)
to decide whether to fix the verifier or retire affected runs.

Reverification covers the run list at its start. Uploads may continue while
the check runs; this does not create an atomic release transaction over D1,
R2 and the Worker. Large or incompatible rule changes need a coordinated
release window.

## Evidence and rollback

The `crimson-land-release` artifact contains the prepared release tarball and
`release.json`: commit, runtime run and SHA-256 hashes of the Worker modules,
site files, verifier and Wrangler config. The deployment summary and
`crimson-land-deployment` artifact retain Wrangler output, including the
Cloudflare version ID. The generated `/deployment.txt` identifies the published commit; the smoke
check rejects a different revision. Production smoke checks cover the site, leaderboard
API, game page, JS/WASM and availability of all three game archives.

A smoke-check failure marks the workflow failed after deployment; it does not
automatically revert production. Review the failure, then use
`npx wrangler rollback <version-id>` from `service/` or the Cloudflare
Deployments page to restore the chosen version. Worker rollback does not undo
D1 migrations or R2 changes. Keep schema changes compatible with the previous
Worker where a code rollback is intended.

Local deployment remains available through `npm --prefix service run deploy`.
Build the verifier first with `uv run python crimson-core/build.py --target wasm`
and perform the same migration and replay checks before publishing locally.
