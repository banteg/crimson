---
tags:
  - contributor
  - setup
---

# Setup

## Environment

- Python 3.13+ with [uv](https://docs.astral.sh/uv/)
- `just` task runner

## First run

```bash
uv sync --group dev
just check
just docs-build
```

## Useful commands

- `just check` — lint, type-check, docs checks, ast-grep scan/tests, and pytest
- `just docs-build` — build docs site
