---
tags:
  - frida
  - differential-sessions
---

## Session 15 (2026-02-13)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `f9f77eaa50a42c5f016a6f73974e91f6abc95de24f43c98ccb30be7d26483973`
- **First mismatch progression:**
  - baseline on this branch before fixes: `tick 1882 (rng_stream_mismatch)`
  - after freeze corpse-gating fix: `tick 3341 (rng_stream_mismatch)`
  - after projectile find-radius epsilon parity fix: `tick 5036 (rng_stream_mismatch)`
  - after capture fire synthesis mapping fix: `tick 5053 (state_mismatch: players[0].pos.x expected=738.8953857421875 actual=738.8964)`

### Key Findings

- Tick `5036` replay fire synthesis missed a valid player shot:
  - capture has player-owned projectile spawns (`actual_type_id=11`) while player weapon is `14` (Plasma Shotgun),
  - `_tick_player_weapon_projectile_spawned` compared spawn type IDs directly against weapon ID and returned false.
- Fixing weapon->projectile type matching removed the `tick 5036` RNG drift; `rng_stream` now matches through that region.
- New first divergence (`tick 5053`) is a small position drift with no RNG activity:
  - `focus-trace --tick 5053`: `rand_calls_total=0`, no collision hits/deaths/sfx,
  - small multi-entity positional deltas are already present by this tick (creatures/projectiles), indicating cumulative simulation drift upstream.
- Diagnostic lead now points to insufficient capture internals for the first causative branch:
  - no `creature_update_micro` rows at focus,
  - required movement turn/target internals are not available in this capture.

### Landed Changes

- `src/crimson/bonuses/freeze.py`
  - added corpse hard-despawn gate (`_CORPSE_DESPAWN_HITBOX = -10.0`) to stop replay-only freeze FX work on already-despawned corpses.
- `src/crimson/projectiles/runtime/collision.py`
  - added `_NATIVE_FIND_RADIUS_MARGIN_EPS = 0.001` to stabilize native-style find-radius branch parity under tiny float drift.
- `src/crimson/original/focus_trace.py`
  - collision tracing now uses the same runtime predicate path used by gameplay collision checks.
- `src/crimson/original/capture.py`
  - `_tick_player_weapon_projectile_spawned` now matches spawn type IDs via `projectile_type_ids_from_weapon_id(weapon_id)` (while preserving direct weapon-ID matching).
- Tooling:
  - `src/crimson/cli.py` + `src/crimson/original/diagnostics_daemon.py`: `original bisect-divergence` now supports cached runner path and `--no-cache`.
  - `src/crimson/cli.py`: `original verify-capture` now supports `--json-out`.
- Tests:
  - `tests/test_original_capture_conversion.py`: added regression for unknown-mode fire synthesis with mapped weapon projectile (`weapon_id=14`, projectile type `11`).
  - `tests/test_projectiles.py`: updated secondary pool speed expectation to float32-fidelity value.

### Validation

- `uv run pytest tests/test_original_capture_conversion.py -k "mapped_weapon_projectile or weapon_switches_in_tick or unknown_mode_without_weapon_match"`
- `uv run pytest tests/test_projectiles.py -k "secondary_projectile_pool"`
- `uv run pytest tests/test_original_diagnostics_daemon.py tests/test_original_capture_verify.py`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/capture_f9f77eaa_fix6_baseline_nocache.json` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 5053 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_f9f77eaa_fix6_focus_5053_nocache.json`
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32 --json-out analysis/frida/reports/capture_f9f77eaa_fix6_verify.json` *(expected non-zero exit while diverged)*
- `just check`

### Outcome / Next Probe

- **Current hard block:** first surviving mismatch is a tiny cumulative movement/state drift (`tick 5053`) without RNG/collision branch evidence at focus, and this capture lacks creature movement micro telemetry required to isolate the first branch split.
- Next required capture should use the current `scripts/frida/gameplay_diff_capture.js` defaults (creature micro telemetry on by default), then re-run baseline triage/focus around the first drift corridor (`~4690..5060`).

---

