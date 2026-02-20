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

- Tests and fixtures
  - Updated strict capture fixtures to use `type` tags for event heads/phase markers:
    - `tests/test_original_capture_conversion.py`
    - `tests/test_original_diagnostics_cache.py`
    - `tests/test_original_capture_divergence_report_summary.py`
    - `tests/test_original_capture_divergence_report_rng_calls.py`
  - Updated strict payload fixture fields for new typed event-head data shapes.

- Validation (current branch)
  - `just check` passes.
  - Full test suite passes (`1318 passed, 7 skipped`).

## Remaining Work

- Continue defensive-coercion cleanup where hard schema is guaranteed
  - Major remaining concentration: `src/crimson/original/capture.py` bootstrap/event payload application paths and coercion helpers.
  - Secondary concentration: remaining dict/coercion wrappers in `src/crimson/original/divergence_report.py` and `src/crimson/original/focus_trace.py`.

- Optional follow-through for full strictness
  - Type additional event-head/phase-marker payloads that still use generic dict payload structs.
  - Keep `msgspec.to_builtins` only at explicit serialization boundaries (`capture.py` dump path and cache metadata serialization).

## Notes

- `handoff.md` is now status-oriented and should be the source of truth for next strict-capture cleanup steps.
