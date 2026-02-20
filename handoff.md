# Strict Capture Parsing Handoff

Updated: 2026-02-20

## Completed Work

Shipped in commit `2a9eccc3` (`refactor(original-capture): enforce strict capture schema parsing`).

- `src/crimson/original/schema.py`
  - Added strict typed structs for diagnostics and snapshots (timing/spawn/rng/player_fire/lifecycle/counters/snapshot globals/status/input/player/alt-weapon).
  - Rewired capture checkpoint/debug/snapshot/tick types to use strict structs.

- `src/crimson/original/capture.py`
  - Removed legacy `f32:` token preprocessing (`_decode_f32_token`, `_decode_f32_tokens`) from stream decode path.
  - Removed legacy optional/fallback behavior in key parsing paths (including missing-owner secondary spawn and missing-player bonus apply fallbacks).
  - Switched multiple flows from dict probing to strict typed access for snapshot/debug/diagnostics.
  - Simplified frame dt / game mode / quest stage access to strict fields.

- `src/crimson/original/diagnostics_cache.py`
  - Migrated tick-lite construction to strict typed diagnostics/snapshot usage.
  - Converted typed counter rows back to dict rows only where needed for serialized cache output.

- Tests updated for strict schema fixtures
  - `tests/test_original_capture_conversion.py`
  - `tests/test_original_capture_verify.py`
  - `tests/test_original_diagnostics_cache.py`
  - `tests/test_original_capture_divergence_report_summary.py`
  - `tests/test_original_capture_divergence_report_rng_calls.py`

- Validation
  - `just check` passes.
  - Full test suite currently passes in this branch (`1318 passed, 7 skipped`).

Completed in current branch (pending merge):

- `src/crimson/original/schema.py`
  - Strictly typed the previously loose event-head payloads:
    - `CaptureEventHeadModeTick`
    - `CaptureEventHeadPlayerFire`
    - `CaptureEventHeadWeaponAssign`
    - `CaptureEventHeadBonusApply`
    - `CaptureEventHeadBonusSpawn`
    - `CaptureEventHeadPerkDelta`
    - `CaptureEventHeadSfx`
  - Switched capture event-head/phase-marker tagged unions to msgspec default tag field (`type`) by removing explicit `tag_field="kind"`.

- `scripts/frida/gameplay_diff_capture.js`
  - Aligned capture emitter output to strict `type`-tagged event heads and phase markers (no `kind` tag field for union dispatch).

- `src/crimson/original/divergence_report.py`
  - Removed `msgspec.to_builtins` tick-row conversion path.
  - Reworked raw run-summary parsing to iterate strict typed capture ticks directly.
  - Replaced raw-debug extraction with strict typed tick-lite construction (`diagnostics_cache._build_tick_lite_row`).

- `src/crimson/original/focus_trace.py`
  - Removed `msgspec.to_builtins` conversions for capture samples/rng.
  - Added strict typed capture tick payload builders.

- `src/crimson/original/creature_trajectory.py`
  - Removed `msgspec.to_builtins` sample/bootstrap conversions.
  - Replaced defensive sample-dict probing with strict fixed-shape sample rows.

- `src/crimson/original/capture.py`
  - Added strict `msgspec.Struct` payload models for replay-side unknown events:
    - bootstrap payload
    - creature spawn payload
    - state transition payload
  - Removed dict-probing fallback parsing in replay event payload helpers.
  - Reworked `apply_capture_bootstrap_payload` to strict typed payload application (no legacy optional dict guards).
  - Removed dead legacy helper usage in bootstrap parsing paths.

- Replay runner/capture tooling strict payload adoption
  - `src/crimson/sim/driver/replay_events.py`
    - Switched creature `added_head` application from dict probing to strict typed row access.
  - `src/crimson/sim/driver/replay_runner.py`
  - `src/crimson/original/diagnostics_cache.py`
  - `src/crimson/original/focus_trace.py`
  - `src/crimson/original/creature_trajectory.py`
  - `src/crimson/original/capture_visualizer.py`
    - All bootstrap payload consumers now read strict typed payload objects (including `quest_session`) with no legacy dict parsing branches.

- Tests and fixtures
  - Updated strict capture fixtures to use `type` tags for event heads/phase markers:
    - `tests/test_original_capture_conversion.py`
    - `tests/test_original_diagnostics_cache.py`
    - `tests/test_original_capture_divergence_report_summary.py`
    - `tests/test_original_capture_divergence_report_rng_calls.py`
  - Updated strict payload fixture fields for new typed event-head data shapes.
  - Updated replay-runner bootstrap fixture payloads to full strict bootstrap schema:
    - `tests/test_replay_runners.py`
  - Updated capture conversion helper tests/expectations for strict typed bootstrap and creature spawn rows:
    - `tests/test_original_capture_conversion.py`

- Validation (current branch)
  - `just check` passes.
  - Full test suite passes (`1318 passed, 7 skipped`).

## Remaining Work

- None for the strict-capture parsing alignment plan in this branch.
- Current status: 100% complete for the planned strict-form capture parser cleanup.

## Notes

- `handoff.md` is now status-oriented and should be the source of truth for next strict-capture cleanup steps.
