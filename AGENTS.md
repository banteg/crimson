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

# Coding Rules (Strictly-Typed + Fail-Fast)

You are working in a modern, **strictly-typed** codebase. You must write code using **Type-Driven Development** and **Fail-Fast** principles. 

If you encounter type checker errors, **FIX THE UNDERLYING SCHEMA**. Do not use runtime casting, `getattr`, or `Any` to silence the type checker.

## 1. NO PARANOID TYPE CASTING
Trust the type hints. If a variable is annotated as `int`, do not wrap it in `int()`. If a function returns a `bool`, do not wrap it in `bool()`.
*   **BAD:** `int(int(self.index) + 1)`
*   **BAD:** `if bool(self.is_active):`
*   **BAD:** `float(f32(float(dt) * float(speed)))`
*   **GOOD:** `self.index + 1`
*   **GOOD:** `if self.is_active:`
*   **GOOD:** `f32(dt * speed)`

## 2. TRUST VALIDATION BOUNDARIES (CRASH ON INVALID DATA)
Once data passes through our parsers (e.g., `msgspec`), treat it as perfectly valid. 
*   **AVOID** write custom coercion helpers (e.g., `_int_or_zero`, `_coerce_blob`).
*   **AVOID** use `try...except ValueError` to return a default value like `0` or `""`. Let the exception bubble up and crash the program.
*   **AVOID** use `isinstance()` or `hasattr()` to check if a domain object has a field. 

## 3. BAN `getattr()` AND `.get()` ON DOMAIN OBJECTS
Structured data must be accessed via direct dot notation.
*   **BAD:** `getattr(player, "health", 0.0)`
*   **BAD:** `message.reason or "rejected"` (If `reason` can be absent, type it as `str | None` and check `if message.reason is not None:`).
*   **GOOD:** `player.health`
*   *(Note: `.get()` is only permitted on actual Python `dict` instances acting as dynamic maps, never on typed objects).*

## 4. NO DICTIONARY DEGRADATION
Keep typed objects typed. Never degrade a `dataclass` or `msgspec.Struct` into a dictionary just to serialize or manipulate it.
*   **AVOID** use `asdict()`, `msgspec.to_builtins()`, or reflection (`fields(obj)`) to repack data into dictionaries.
*   **AVOID** type hint a field as `dict[str, Any]` or `dict[str, object]`. Define a strict `Struct` or `dataclass` for the nested shape.

## 5. NO SHIMS OR LEGACY WRAPPERS
If a schema or interface changes, update the downstream consumers directly. 
*   **AVOID** create `legacy_*` files.
*   **AVOID** use `import *` to re-export old modules to satisfy old code.
