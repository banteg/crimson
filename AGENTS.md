# Crimson Agent Notes

We are decompiling and porting an old game. We aim for high fidelity to the original.

- Project docs: [`docs/`](docs/)
- Rewrite overview: [`docs/rewrite/index.md`](docs/rewrite/index.md)
- Rewrite status / parity snapshot: [`docs/rewrite/status.md`](docs/rewrite/status.md)
- Authoritative decompiles and analysis artifacts: [`analysis/`](analysis/)
- Rewrite implementation under development: [`src/`](src/)

For deterministic gameplay code, prefer native float32 fidelity over readability:
- Keep decompiled float32 constants/rounding behavior when they affect simulation.
- Do not normalize values like `0.6000000238418579 -> 0.6` in parity-critical paths unless captures/tests prove no behavioral change.

For capture-driven parity investigations (when you are handed only a fresh capture file), start with:
- [`docs/frida/differential-playbook.md`](docs/frida/differential-playbook.md)

# Pre-commit

Run `just check` before commits.

# Ast-grep

For structural search / codemods, prefer ast-grep over regex-only edits:
- Project config: [`sgconfig.yml`](sgconfig.yml)
- Rules/tests location: [`tools/ast-grep/`](tools/ast-grep/)
- Run checks with `just check`

# Pull Requests

When creating pull requests with `gh`:
- Do not pass multiline bodies via `--body` with escaped `\n` inside shell quotes.
- Write the PR description to a markdown file (or heredoc) and use `gh pr create --body-file <file>` / `gh pr edit --body-file <file>`.
- After creating/updating a PR, verify formatting with `gh pr view`.

# Coding Guidelines (Typed, Fail-Fast, Validate at Edges)

Principles > rules. Don’t make code longer/uglier just to satisfy a guideline.

## Model
- Validate/parse at **boundaries** (IO/CLI/JSON/msgpack). Inside domain, assume validated objects are correct.
- Types are design: if ty complains, **fix schema/boundary**, not with casts/`Any`.
- Fail fast internally; don’t hide impossible states with defaults.

## Do
- Use values directly (no redundant `int(x)` when `x: int`).
- Use explicit types for optional data (`T | None`) and handle it intentionally.
- Keep typed objects typed during computation.
- Convert to dict/builtins **only at edges** (serialization/logging/tests/interop) using standard helpers/serializers.

## Avoid (smells)
- Defensive runtime checks in domain (`isinstance/hasattr`, “just in case” `try/except ValueError`).
- `getattr()` / `.get()` on typed models to dodge typing (ok for real dynamic dicts, or narrow tooling).
- Hand-written field-by-field converters/mappers to comply with style—use serializers or small DTOs.
- Thin duck typing protocols
- Do not add legacy wrappers, do all changes cutover style.

## Schema changes
Update callers directly. Keep schemas versioned, only support the latest version.
If a compat layer is needed, keep it small, local, and temporary (with removal note).

