---
name: crimson-release
description: Prepare or publish a Crimson patch, minor, or development release with changelog notes, version and lock updates, validation, and tag-triggered publishing.
---

# Crimson Release

## Scope and version

- Honor the requested version or bump. Otherwise use patch for compatible fixes/performance improvements, minor for new player-facing features or replay-format changes, and dev for development builds. Ask only if the release scope is ambiguous.
- A request to cut/publish a release authorizes the release commit, tag, and push. If the user asks only to prepare a release, finish the notes, version changes, and checks, then stop before commit/tag/push until publishing is authorized.
- Check `CONTRIBUTING.md`, the latest local/remote release tags, recent release commits, and `.github/workflows/release.yml`. Recent releases use `v<version>` tags and notes extracted from `CHANGELOG.md`.

## Prepare

1. Inspect the branch and `git status --porcelain`. Use an up-to-date `master` or a clean isolated worktree based on it; preserve unrelated work. Install the repository hooks for a new worktree.
2. Run `just check` before changing the version. Resolve new failures before continuing. For gameplay changes, also check the final gameplay commit's CI parity gates and relevant native/replay evidence.
3. Review commits since the previous release. Add `## <version>` to `CHANGELOG.md`, using its existing player-facing style and an `Under the hood` section when useful. Describe observable changes; qualify measured performance by workload and distinguish headless from rendered timings.
4. Run `uv version --bump <patch|minor|dev>` (or the explicit version), then `uv lock`. Inspect the diff: the package and its editable lock entry should match, with no unrelated dependency churn.
5. Validate the release section exactly as the workflow extracts it:
   ```bash
   version="$(uv version --short)"
   awk -v version="$version" '/^## / { section = ($2 == version); next } section' CHANGELOG.md > /tmp/crimson-release-notes.md
   test -s /tmp/crimson-release-notes.md
   ```
   Read the extracted notes and run `uv lock --check`, `uv build`, and checks appropriate to any additional edits. Confirm the wheel/sdist version matches. If preparation is all that was requested, present the diff and validation results here.

## Publish when authorized

1. Review `git diff` and stage only the intended release files, normally `CHANGELOG.md`, `pyproject.toml`, and `uv.lock`. Keep unrelated fixes or skill edits in separate conventional commits.
2. Commit with a conventional title, for example `chore(release): release <version>`. Tag the final validated release head, including any final content fixes; the version-bump commit need not be the tagged head.
3. Create an annotated `v<version>` tag, then push the intended branch and tag. For an isolated preparation branch, integrate it into `master` before tagging. Do not force-push or move an existing published tag.
4. Watch the tag-triggered Release workflow. It builds wheel/sdist, publishes to PyPI, creates the GitHub release from the changelog section, and sends the configured release announcement. Do not create a duplicate GitHub release or send the announcement manually.
5. Verify the remote tag resolves to the intended commit, the Release workflow succeeds, the GitHub release has the expected notes/assets, and PyPI serves the expected version. On failure, inspect the failed job and retry only the failed work when safe; do not republish different bytes under an existing version.
