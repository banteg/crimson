---
tags:
  - frida
  - differential-sessions
---

## Session 7 (2026-02-11)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `16f67e1397e4ec0ee7209aec07a5f1eb604c574a52249df1ebf74826dd1441d1`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_16f67e_abandon_baseline.json`
- **First mismatch:** `tick 29 (players[0].pos.x, players[0].pos.y)`

### Key Findings

- Earliest drift is pre-combat movement (`tick 29`) with no RNG mismatch (`rand_calls delta = 0`), indicating input reconstruction/capture mismatch rather than simulation-side combat logic.
- Capture telemetry at `tick 29` shows `turn_left_pressed=true` and no forward key in `input_player_keys`, while `input_approx.move_dy=-2.227553367614746` indicates forward-like motion was applied by native.
- Static analysis of `player_update` at `0x004136b0` shows that single-player
  alternate bindings use `grim_is_key_down` fallback checks when the primary
  binding is not active.
- Grim vtable mapping confirms slot `0x44` is `grim_is_key_down`
  (`analysis/ghidra/derived/grim2d_vtable_map.csv:19`); consult the Grim
  function at `0x100073d0` for the current tool view.

### Landed Changes

- Updated `scripts/frida/gameplay_diff_capture.js`:
  - hook `grim_is_key_down` (`0x00007320`) alongside existing input hooks,
  - map single-player `alternate_single` bindings (`move_forward/backward`, `turn_left/right`, `fire`) into `input_player_keys`,
  - treat `grim_is_key_down` as a `fire_down` source and include `player_alt_fire_key` in primary-fire detection.
- Updated `src/crimson/original/capture.py`:
  - removed replay input fallbacks/synthesis (no merge from `input_approx` key booleans, no `input_queries` fire fallback, no synthetic fire/reload edges),
  - accepted both `f32:XXXXXXXX` and `f32:0xXXXXXXXX` float tokens,
  - seed inference now prefers per-draw `state_before_u32` when available.
- Updated `tests/test_original_capture_conversion.py` with regressions for:
  - `f32:0x...` decoding,
  - strict no-fallback fire/reload behavior,
  - seed inference from `state_before_u32`.

### Validation

- `uv run pytest tests/test_original_capture_conversion.py`
- `just check`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_16f67e_abandon_baseline.json` *(expected non-zero exit while diverged)*

### Outcome / Next Probe

- This capture SHA family is now **abandoned** for parity work; input telemetry was incomplete for single-player alternate-key paths.
- Record a fresh capture with the updated `scripts/frida/gameplay_diff_capture.js` and start the next session on the new SHA.
- Keep replay conversion strict (no legacy fallbacks) so any future telemetry gaps fail fast and are fixed in instrumentation.

---
