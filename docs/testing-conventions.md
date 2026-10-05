---
tags:
  - contributor
  - testing
---

# Testing Conventions

This project prioritizes deterministic parity with the original executable. The test suite should favor stable behavior checks while keeping tests maintainable.

## Mocking and Patching

- Use `pytest-mock` (`mocker`) as the default mechanism for spies and patches.
- Prefer `mocker.patch.object(...)` over string-target `mocker.patch(...)`.
- Prefer mock assertions (`assert_called_once_with`, `mock_calls`) over ad-hoc closures plus mutable lists.
- Avoid string-target `monkeypatch.setattr("...rl...")` for Raylib calls; use `mocker`-based patches instead.
- Reserve `monkeypatch` for environment variables, filesystem/path mutation, or object-target overrides where `mocker` is not a fit.

## Raylib Access

- Runtime code under `src/` must import Raylib through `grim.raylib_api`:
  - `from grim.raylib_api import rl`
  - `from grim.raylib_api import rd`
- Do not import `pyray` or `raylib.defines` directly from `src/` modules.

## Float Assertions

- Use `tests.support.helpers.assert_float_close(actual, expected)` for scalar float parity checks.
- The canonical absolute tolerance is `1e-9`.

## RNG Assertions

- Use `tests.support.helpers.assert_rng_progression(...)` with a scripted `tests.support.helpers.ScriptedCrand` or a real `Crand` for deterministic RNG checks.
- Assert draw budget (`expected_draws`) when native parity defines an exact call budget.
- Assert state progression (`expected_after_state`) when call ordering is behaviorally significant.
- Use both budget and state in parity-critical paths (projectile/death planning, branch-sensitive effects).
- Use `min_draws` only when a branch must consume RNG but the exact budget is intentionally non-contractual.

## Suite Layout

- Place tests under the nearest domain directory (`tests/perks/`, `tests/sim/`, `tests/replay/`, `tests/render/`, and similar) instead of adding new top-level `tests/test_*.py` files.
- Keep shared builders, fixtures-as-code, and assertion helpers under `tests/support/`.
- Keep binary/static fixtures under `tests/fixtures/`.
- Keep syrupy snapshots in `__snapshots__/` beside the owning test package.
- Prefer adding domain-specific `conftest.py` files or directory-based collection rules over filename-prefix conventions.

## Snapshot-First Testing

- Prefer syrupy snapshots for high-structure payloads and broad regressions.
- Keep explicit assertions for critical invariants (for example deterministic RNG state/hash or exact event semantics).

## Trace and Replay Test Data

- To add a recorded replay fixture, play the run with `uv run crimson --replay-checkpoints`, then copy the
  saved `<name>.crd` and its `<name>.crd.chk` checkpoint sidecar from the runtime `replays/` directory into
  `tests/fixtures/replays/`. The fixture tests replay it headlessly and compare every tick's checkpoint;
  `uv run crimson replay verify-checkpoints tests/fixtures/replays/<name>.crd` runs the same check.
- A checkpoint pins the RNG state after its tick, which a reorder of draws within the tick leaves unchanged,
  so it also carries `rng_callers_crc32`: a CRC32 of the tick's RNG call sites in draw order. A reorder fails
  at its tick, and `verify-checkpoints` lists the tick's call sites.
- Keep serialization at API/file boundaries.
- For negative validation tests, it is acceptable to inject malformed rows directly at the boundary layer.

## Guardrails

Ast-grep rules enforce key constraints:

- no direct `pyray` imports in `src/`
- no string-target `mocker.patch("...")` in tests
- no string-target Raylib `monkeypatch.setattr("...rl...")` in tests
- no list-append side-effect spies inside patch hooks
- no `inspect.stack()` in tests
- no raylib screen-size or mouse reads in `src/`; read them through `grim.canvas`
- no ad-hoc dt-to-milliseconds integer conversions in the sim and replay code; use `ftol_ms_i32()`
