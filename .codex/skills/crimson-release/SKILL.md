---
name: crimson-release
description: Run the Crimson release/dev bump checklist (ruff, pytest, uv version bump, uv lock), then create a conventional-commit release commit, tag it, and push. Use when cutting a release/tag for this repo or doing the post-release dev bump.
---

# Crimson Release

## Goal

Produce a clean release/dev-bump commit + tag for this repo by running the checklist below in order.

## Workflow

### Pre-flight

- Ensure the working tree is clean: `git status --porcelain` prints nothing.
- Ensure the branch is correct (usually `master`).
- Ask for confirmation before any of: `git commit`, `git tag`, `git push`.

### 0) Lint

Run: `ruff check src tests`

### 1) Tests

Run: `uv run pytest`

### 2) Bump dev version

Run: `uv version --bump dev`

Capture the resulting version string (use `uv version` if needed).

### 3) Refresh lockfile

Run: `uv lock`

### 4) Commit

- Verify the diff is expected: `git diff --stat`.
- Stage: `git add -A`.
- Commit using conventional commits (example): `git commit -m "chore(release): bump dev version to <version>"`.

### 5) Tag

- Prefer an annotated tag.
- Derive the tag from the version (common pattern): `v<version>`.
- If tag format is unclear, ask before creating it.

Example:

```bash
git tag -a "v<version>" -m "v<version>"
```

### 6) Push

- Push branch and tag.
- Prefer: `git push --follow-tags`.
- If the remote/tag needs to be explicit, push both separately.

## Sanity checks

- Ensure only expected files changed (typically `pyproject.toml` and `uv.lock`).
- Stop and ask if new failures appear or unexpected files change.
