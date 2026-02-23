---
tags:
  - frida
  - differential-sessions
---

## Session 5 (2026-02-10)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `508bcc903432247cba3c284523b67f750df141d72b647d7d8464e5d324b08279`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_508bcc_divergence_after_inputkeys_fix.json`
- **First mismatch progression:**
  - initial (before replay input-key fix): `tick 61 (players[0].pos.x, players[0].pos.y)`
  - after replay input-key reconstruction update: `tick 3254 (players[0].pos.x, players[0].pos.y)`

### Key Findings

- Capture SHA differs from Session 4 and should be tracked as a new session family.
- Capture stream is valid JSONL with `11190` tick rows and no terminal capture marker (expected for current writer behavior).
- In this capture family, `input_approx.move_dx/move_dy` appears to reflect runtime movement deltas, not stable raw input intent; replaying them directly caused a false early drift at `tick 61`.
- Reconstructing replay input from `input_player_keys` (with fallback merge) moved the frontier from `tick 61` to `tick 3254`.
- Current lead stack on this SHA is:
  - unresolved RNG accounting/branch parity around `tick 3050` (`perk_select_random` caller),
  - then movement/position drift at `tick 3254`,
  - with an opposite-direction key conflict observed in capture key-state at the focus tick.

### Landed Changes

- Updated `src/crimson/original/capture.py`:
  - infer digital movement capability from both `input_approx` and `input_player_keys`,
  - prefer `input_player_keys` for movement/fire/reload reconstruction when present,
  - keep compatibility fallbacks for partial captures.
- Updated `scripts/frida/gameplay_diff_capture.js`:
  - mirror key-state fields and `aim_heading` into `input_approx` to reduce schema ambiguity for downstream consumers.
- Added regression coverage in `tests/test_original_capture_conversion.py` for key-state-priority reconstruction and fire/reload edge handling.

### Validation

- `uv run pytest tests/test_original_capture_conversion.py`
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --max-field-diffs 32` *(expected non-zero exit while diverged)*
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_508bcc_divergence_after_inputkeys_fix.json` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 3050 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_508bcc_focus_3050_after_inputkeys_fix.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 3254 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_508bcc_focus_3254_after_inputkeys_fix.json`

### Outcome / Next Probe

- Use the updated Frida script in the next capture so `input_approx` carries mirrored key-state consistently.
- After that re-capture confirms stable key-state telemetry, remove temporary replay fallbacks in `src/crimson/original/capture.py` that synthesize/mix input from partial fields.
- Then continue RNG/branch investigation at `tick 3050` (`perk_select_random`) before re-evaluating the `tick 3254` movement drift.

---

