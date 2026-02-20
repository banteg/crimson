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

Run `just check` before commits.

For structural search / codemods, prefer ast-grep over regex-only edits:
- Project config: [`sgconfig.yml`](sgconfig.yml)
- Rules/tests location: [`tools/ast-grep/`](tools/ast-grep/)
- Run checks with `just check`

When creating pull requests with `gh`:
- Do not pass multiline bodies via `--body` with escaped `\n` inside shell quotes.
- Write the PR description to a markdown file (or heredoc) and use `gh pr create --body-file <file>` / `gh pr edit --body-file <file>`.
- After creating/updating a PR, verify formatting with `gh pr view`.

# Coding rules (typed + fail-fast)

You are working in a modern, **strictly-typed** codebase. All inputs are **validated at the boundaries** (e.g., `msgspec`).
Write code using **Type-Driven Development** and **Fail-Fast** principles.

## Rules

1. **Trust validation boundaries**
   - After parsing/validation, treat objects as schema-correct.
   - **Do not** add defensive checks like `isinstance()`, `hasattr()`, or “just in case” branching.
   - **Do not** write custom coercion helpers (`_int_or`, `_float_or`, `_coerce_*`, etc.).

2. **Use dot access; ban `.get()` on domain objects**
   - Access structured data via attributes (`obj.field`), not `dict.get()`.
   - Only use `.get()` for genuinely dynamic maps/caches.
   - If a field may be absent, model it as `T | None` and handle explicitly:
     - `if obj.field is not None: ...`

3. **No dictionary degradation**
   - Keep typed objects typed; don’t repack into untyped dicts to “make it work”.
   - **Do not** use `msgspec.to_builtins()`, `asdict()`, or manual dict repacking for domain data.
   - Avoid `dict[str, Any]` / `dict[str, object]` for shaped data—define a `Struct`/`dataclass`.

4. **No shims; refactor consumers**
   - When schemas/types change, update downstream consumers to use the new types directly.
   - **Do not** add translation layers, “Lite” wrappers, or compatibility shims to protect legacy code.

5. **Fail fast and loud**
   - We control producers and consumers; broken invariants should crash immediately.
   - **Do not** swallow exceptions or invent fallback defaults (`value or -1`, `value or ""`, etc.).
   - Let real errors surface (`AttributeError`, `TypeError`, `KeyError`, etc.).
