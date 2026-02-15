---
name: crimson-release
description: Run the Crimson release checklist (just check, uv version bump, uv lock), then create a conventional-commit release commit, tag it, and push. Default bump is minor (use dev bump when needed).
---

# Crimson Release

## Goal

Produce a clean release commit + tag for this repo by running the checklist below in order.

## Workflow

### Pre-flight

- Ensure the working tree is clean: `git status --porcelain` prints nothing.
- Ensure the branch is correct (usually `master`).
- Ask for confirmation before any of: `git commit`, `git tag`, `git push`.

### 0) Checks

Run: `just check`

### 1) Bump version (default: minor)

Run: `uv version --bump minor`

If you need a dev-only bump instead (e.g., `0.1.0.dev29 -> 0.1.0.dev30`), run: `uv version --bump dev`

Capture the resulting version string (use `uv version` if needed).

### 2) Refresh lockfile

Run: `uv lock`

### 3) Commit

- Verify the diff is expected: `git diff --stat`.
- Stage: `git add -A`.
- Commit using conventional commits (example): `git commit -m "chore(release): bump version to <version>"`.

### 4) Tag

- Prefer an annotated tag.
- Derive the tag from the version (common pattern): `v<version>`.
- If tag format is unclear, ask before creating it.

Example:

```bash
git tag -a "v<version>" -m "v<version>"
```

### 5) Push

- Push branch and tag.
- Prefer: `git push --follow-tags`.
- If the remote/tag needs to be explicit, push both separately.

## Sanity checks

- Ensure only expected files changed (typically `pyproject.toml` and `uv.lock`).
- Stop and ask if new failures appear or unexpected files change.
