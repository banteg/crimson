---
tags:
  - contributor
  - workflows
---

# Workflows

Operational runbooks and recurring maintenance flows.

[Deploy crimson.land](deploy.md) through the manual Actions workflow, including
production credentials, replay checks and rollback.

## Releases

Open a `chore(release): release X.Y.Z` PR that bumps the version in
`pyproject.toml` and `uv.lock` and adds a `## X.Y.Z` section to `CHANGELOG.md`.
After it merges, push an annotated `vX.Y.Z` tag on the merge commit. The Release
workflow checks the tag against the package version, takes the release notes
from that changelog section, publishes to PyPI and creates the GitHub release.
Deploy crimson.land afterwards so the site and browser game carry the release,
or before pushing the tag when the release bumps the replay format
([replay format bumps](deploy.md#replay-format-bumps)).

## Documentation maintenance

Keep each behavior or contract in one reference page. Update the owning page
when a hypothesis is resolved, with a native function/address or reproducible
artifact comparison. Distinguish native behavior, port implementation and
intentional differences. Keep uncertainty only where the evidence is incomplete.

Retire completed migration plans after incorporating their lasting contracts.
Store unique historical observations with the analysis artifacts, clearly dated;
do not keep completed checklists as permanent status pages. Use command help for
option lists and the [format matrix](../../rewrite/cdt-trace-format.md#versioning) for
current versions rather than copying them into every workflow.

Run `just docs-check` and `just docs-build`. The checker covers internal Markdown
links, nav coverage, tags, literal source paths and machine-local links. Source
references should name repository-relative modules or symbols; generated
output directories are not required to exist in a fresh checkout. Regression
tests also check the documented format matrix against the implementation.
