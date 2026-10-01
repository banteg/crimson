We are decompiling and porting an old game. The goal is **deterministic, evidence-backed behavioral parity** with the original.

## project layout

```
src/
  crimson/          game logic: modes, weapons, perks, creatures, UI, replay
  grim/             engine layer: raylib wrapper, PAQ/JAZ decoders, audio, fonts
decomp/             recovered C/C++ source and builds.json (every pinned build)
crimson-re/         reverse-engineering tools (`crimson match|native|dbg`), a workspace package kept out of the game wheel
crimson-zig/        Zig port (frozen): replay verifier, desktop runtime, WASM
analysis/
  ghidra/           name/type maps (source of truth) and structured snapshots
  binary_ninja/     preferred live analysis databases
  ida/              structured function/import/string snapshots
  decomp/           decomp.dev evidence and per-build maps
  frida/            trace summaries from past Frida sessions
docs/               100+ pages: formats, structs, algorithms, parity tracking
scripts/            analysis and utility tools
tests/              gameplay, replay, parity and regression tests
```

## parity workflow

1. Recover structure and intent from static analysis. Names and types live in `analysis/ghidra/maps/`; consult function views in Binary Ninja, IDA, then Ghidra with the address-keyed workflow in `analysis/README.md`.
2. Settle ambiguous behavior against the original code under the Unicorn [native execution oracle](docs/verification/differential-testing/native-oracle.md), which checks port code bit for bit.
3. Port behavior into `src/` with deterministic simulation contracts. Float behavior is part of the contract: see the [float parity policy](docs/rewrite/float-parity-policy.md).
4. Verify against recorded replays and their per-tick checkpoints with headless tools.

[provenance.md](docs/contributor/project-tracking/provenance.md) has the exact binary hashes of the target build.

## core priorities

1. **Deterministic parity + evidence-backed correctness** If rules conflict, preserve native-faithful behavior and prove it with captures/replays/deterministic tests.
2. **Structural simplicity** Prefer deleting complexity over adding layers.
3. **UX polish** Only after parity is preserved (unless explicitly required and proven not to change parity-critical behavior).

### prove it works
- Do **not** rush to claim parity from “it compiles,” lint success, or summaries.
- Verification must use **real artifacts and real pathways** (capture verification, replay verification, deterministic tests).

### f32 fidelity over readability
- Keep decompiled `float32` constants and rounding behavior exactly as-is **when it affects simulation**.
- Do **not** normalize constants like `0.6000000238418579 -> 0.6` unless tests/captures prove no behavioral change.
- Be suspicious of any “cleanup” that changes: float constants, operation ordering. RNG consumption, branch conditions.

### validate at edges, trust inside
- **Validate/parse at boundaries** (IO/CLI/JSON/msgpack/network messages).
- **Inside the domain**, assume validated typed objects are correct: Fail fast on impossible states. Do not hide errors with defaults/fallbacks.
- Keep objects **typed during computation**. Convert to dict/builtins **only at edges** (serialization/logging/tests/interop) via standard serializers/helpers.

### types are design
- If `ty`/typing complains, **fix the schema/boundary/model**.
- Avoid casting to `Any` or duct-taping with `.get()`/`getattr()` to dodge typing.

### fix root causes
- Do not add “just in case” guards to silence crashes/divergences (extra `None` checks, broad tolerances, fallback defaults, epsilons, off-by-one guards).
- Trace mismatches to bedrock: float rounding/order, misread decompile, wrong table/enum mapping

## preferred refactor style

### migrate callers, then delete legacy APIs
- Default posture: **cutover refactors**.
- Update all internal callers in one wave; delete old APIs/schemas/tests for deprecated behavior.
- Do **not** add long-lived compatibility wrappers. If compatibility is absolutely required: keep it **small, local, temporary**, mark it clearly for removal (with a removal note)

### subtract before you add
- Before introducing a new abstraction or subsystem, remove dead code, obsolete wrappers, and duplicate paths in the target area.

### outcome-oriented execution
- It’s OK for intermediate steps to break **if** the breakage is scoped and planned.
- Final state must be coherent, verified, and free of permanent temporary scaffolding.

### redesign from first principles
- For major architectural or schema changes:
  - define the ideal target state as if this requirement existed from day one
  - land incrementally toward that target
  - do not bolt on special cases that preserve avoidable complexity

### exhaust the design space
Only when **not dictated by the original binary** and there are multiple viable options:
- sketch 2–3 concrete alternatives
- pick based on parity risk, maintainability, and testability
Skip this for mechanical ports and obvious root-cause fixes.

## avoid these smells (especially in gameplay/domain code)

- Defensive runtime checks deep in the domain:
  - `isinstance`, `hasattr`, “just in case” `try/except ValueError`
- `.get()` / `getattr()` on typed models to dodge typing (OK for truly dynamic dicts or narrow tooling)
- Thin duck typing protocols that blur invariants
- Hand-written field-by-field mappers just to satisfy style (prefer serializers/DTOs)
- Long-lived “compat” layers when internal callers can be migrated

## encode lessons in structure

If a mistake or review comment repeats, convert it into enforcement: tests / snapshots / invariants, `ast-grep` rules, typed schemas and decoders, scripts/automation.

Text rules are forgettable; structural rules enforce themselves.

## verification commands

### everyday commands

```bash
uv run pytest              # test suite
uv run ruff check .        # lint
uv run ty check src tests  # type check
ast-grep scan              # ast-grep code scan
just check                 # all of the above
zensical serve             # docs site from docs/ (uv tool install zensical)
```

### required pre-commit checks
- Install hooks once per clone/worktree: `prek install -c prek.toml -t pre-commit -t pre-push`
- `pre-commit` runs fast checks only (ruff/ty/docs/ast-grep/ziglint) and is file-scoped.
- `pre-push` runs the fast packaging and Zig unit-test checks and is file-scoped.
- Full pytest runs in CI. The Zig port is frozen: its tests are skipped unless you pass `--run-zig`, and
  its CI only runs when `crimson-zig/` changes.
- ziglint behavior is configured in `crimson-zig/.ziglint.zon`.
- Manual runs:
  - `prek run --stage pre-commit`
  - `prek run --stage pre-push`
  - `prek run py-pytest`, `prek run zig-release`, or `prek run zig-wasm`
- CI-equivalent local run:
  - Python/docs/tooling changes (`src/`, `tests/`, `docs/`, `tools/`, etc.): `just check && uv build`
  - Zig-only changes (`crimson-zig/`): `just check-zig`
  - Mixed Zig + Python/docs/tooling changes: run both

## quick playbooks

### parity bug investigation
1. Reproduce using the canonical replay.
2. Generate a divergence report (`dbg diff`/`dbg bisect` on recorded traces).
3. Isolate the **first sustained mismatch** and identify the subsystem.
4. Fix the **root cause** (not the symptom).
5. Re-run the **same** replay and confirm the mismatch moves/disappears for the right reason.
6. Add a regression test that locks the discovered behavior.

### API/schema refactor (cutover wave)
1. Define target API and invariants (ordering, ownership, serialization boundaries).
2. Migrate all internal callers in one wave.
3. Delete legacy APIs/re-exports/tests in the same wave.
4. Search for remaining references to old surfaces and remove them.
5. Verify with `just check` / `just check-zig` and parity tests/artifacts.

### docs/tooling changes
1. Keep guidance aligned with parity-first + typed-boundary policy.
2. When guidance repeats, encode it structurally (rules/tests) where possible.
3. Run `just check`.

## structural search / codemods: prefer ast-grep

- Prefer `ast-grep` over regex-only edits for structural transformations.

## pull requests (gh cli hygiene)

When using `gh`:

- PR title must be in the form of a conventional commit
- When ask to merge, use `gh pr merge --squash <pr>`

- To avoid escaping issues, write the PR description to a file and use:
  - `gh pr create --body-file <file>`
  - `gh pr edit --body-file <file>`

---

## reminder: when in doubt
- Choose fidelity and determinism over cleanliness.
- Prove behavior with decompile/captures/replays/tests, not intuition.
- Fix schemas/types/contracts at boundaries rather than weakening the domain.
- Delete old paths rather than supporting two worlds.
