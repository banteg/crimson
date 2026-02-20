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

## Remaining Work

- Strictly type remaining event head payloads in schema (still `data: dict[str, object]`):
  - `CaptureEventHeadModeTick`
  - `CaptureEventHeadPlayerFire`
  - `CaptureEventHeadWeaponAssign`
  - `CaptureEventHeadBonusApply`
  - `CaptureEventHeadBonusSpawn`
  - `CaptureEventHeadPerkDelta`
  - `CaptureEventHeadSfx`

- Remove unneeded `msgspec.to_builtins` usage in analysis paths (keep only final serialization boundaries where appropriate):
  - `src/crimson/original/divergence_report.py`
  - `src/crimson/original/focus_trace.py`
  - `src/crimson/original/creature_trajectory.py`
  - (review `capture.py` and `diagnostics_cache.py` to keep only output serialization conversions)

- Continue defensive-coercion cleanup where hard schema is guaranteed
  - Major remaining concentration: `capture.py` bootstrap/event payload application paths and analysis helpers.
  - Secondary concentration: `divergence_report.py` and `focus_trace.py` dict/coercion wrappers.

- JS emitter alignment follow-through
  - Ensure capture producer no longer emits legacy `f32:` token strings.
  - Keep parser strict and fail-fast for schema violations.

## Notes

- `handoff.md` is now status-oriented and should be the source of truth for next strict-capture cleanup steps.
