---
name: ast-grep
description: Use ast-grep (`sg`) for Python and Zig structural code exploration, mechanical codemods, and rule maintenance in this repo. Use this when you need syntax-aware search/replace (instead of regex), to add/update ast-grep rules in `tools/ast-grep/`, or to verify rule behavior with `sg scan` and `sg test`. For Zig, use `sgconfig.local.yml` so the custom parser is loaded.
---

# Ast-grep

Prefer `sg` for structural exploration and mechanical rewrites in Python/Zig code.

## Quick Start

- Run policy checks: `sg scan`
- Run rule tests + snapshots: `sg test`
- Run full local check chain: `just check`
- For Zig parsing/local Zig rules: add `-c sgconfig.local.yml`

## Structural Exploration

Use `sg run` with `-p` for ad-hoc structural queries.

Python examples:

```bash
sg run -l python -p 'config.data.get($$$ARGS)' src tests
sg run -l python -p 'except Exception: pass' src tests
```

Zig examples (must use local config):

```bash
sg run -c sgconfig.local.yml -l zig -p '@intFromFloat(@round(_DT * 1000.0))' crimson-zig/src
sg run -c sgconfig.local.yml -l zig -p 'const _NAME = _TYPE{};' crimson-zig/src
```

Zig metavariables use `_VAR` style in patterns (for example `_EXPR`, `_TYPE`).

## Mechanical Codemods

1. Start narrow (single directory or file set).
2. Prototype match/rewrite:

```bash
sg run -l python -p 'config.data.get($$$ARGS)' -r 'config.get($$$ARGS)' src
```

3. Apply intentionally:
- Interactive: add `-i`
- Apply all matches: add `-U`
4. Review `git diff` and rerun `sg scan` and `sg test`.

For Zig typed-empty-init codemods, reuse the existing recipe:

```bash
just zig-z004-fix
```

## Repo Rule Layout

- Main config: `sgconfig.yml`
- Main rules: `tools/ast-grep/rules/`
- Main tests: `tools/ast-grep/tests/`
- Local config: `sgconfig.local.yml`
- Local rules: `tools/ast-grep/rules-local/`
- Local tests: `tools/ast-grep/tests-local/`
- Shared utils: `tools/ast-grep/utils/`

Rules are YAML files with `id`, `language`, `severity`, `message`, path scope (`files`/`ignores`), and `rule` matcher. Keep `id`, rule filename, and test filename aligned.

## Repo Test Layout

Each test file mirrors a rule ID and includes:
- `valid`: examples that must not match
- `invalid`: examples that must match

Snapshot files live in `__snapshots__/` beside tests and are checked by `sg test`.

Useful commands:

```bash
# all configured tests
sg test

# one rule by id regex
sg test -f no-config-data-get

# include local Zig tests/rules config
sg test -c sgconfig.local.yml

# refresh all snapshots after intentional rule changes
sg test -U
```

## Repo Policy Notes

From `CONTRIBUTING.md`:
- Prefer ast-grep over regex-only edits for structural transforms.
- For Zig, use `sgconfig.local.yml` to load the custom parser.
- When mistakes repeat, encode them as rules/tests/snapshots.
