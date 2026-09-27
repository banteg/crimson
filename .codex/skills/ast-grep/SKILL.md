---
name: ast-grep
description: Use ast-grep for Python structural code exploration, mechanical codemods, and rule maintenance in this repo. Use this when you need syntax-aware search/replace (instead of regex), to add/update ast-grep rules in `tools/ast-grep/`, or to verify rule behavior with `ast-grep scan` and `ast-grep test`.
---

# Ast-grep

Prefer `ast-grep` for structural exploration and mechanical rewrites in Python code. It has no bundled Zig
parser; Zig style is checked by ziglint.

## Quick Start

- Run policy checks: `ast-grep scan`
- Run rule tests + snapshots: `ast-grep test`
- Run full local check chain: `just check`

## Structural Exploration

Use `ast-grep run` with `-p` for ad-hoc structural queries:

```bash
ast-grep run -l python -p 'getattr($OBJ, $ATTR, $DEFAULT)' src tests
ast-grep run -l python -p 'int(round($DT * 1000.0))' src/crimson/sim
```

## Mechanical Codemods

1. Start narrow (single directory or file set).
2. Prototype match/rewrite:

```bash
ast-grep run -l python -p 'int(round($DT * 1000.0))' -r 'ftol_ms_i32($DT)' src/crimson/sim
```

3. Apply intentionally:
- Interactive: add `-i`
- Apply all matches: add `-U`
4. Review `git diff` and rerun `ast-grep scan` and `ast-grep test`.

## Repo Rule Layout

- Config: `sgconfig.yml`
- Rules: `tools/ast-grep/rules/`
- Tests: `tools/ast-grep/tests/`

Rules are YAML files with `id`, `language`, `severity`, `message`, path scope (`files`/`ignores`), and `rule` matcher. Keep `id`, rule filename, and test filename aligned. Use `severity: error`: prek only shows the output of failing hooks, so warnings go unseen.

## Repo Test Layout

Each test file mirrors a rule ID and includes:
- `valid`: examples that must not match
- `invalid`: examples that must match

Snapshot files live in `__snapshots__/` beside tests and are checked by `ast-grep test`.

Useful commands:

```bash
# all configured tests
ast-grep test

# one rule by id regex
ast-grep test -f no-string-mocker-patch

# refresh all snapshots after intentional rule changes
ast-grep test -U
```

## Repo Policy Notes

From `CONTRIBUTING.md`:
- Prefer ast-grep over regex-only edits for structural transforms.
- When mistakes repeat, encode them as rules/tests/snapshots.
