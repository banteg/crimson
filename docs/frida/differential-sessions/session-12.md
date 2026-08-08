---
tags:
  - frida
  - differential-sessions
---

## Session 12 (2026-02-12)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `25ef6718185ed9615d1a172caec2870689148723bb27ab113caee0b170b22599`
- **First mismatch progression:**
  - sustained (`divergence-report` + `bisect-divergence`): `tick 570 (rng_stream_mismatch)`
  - checkpoint-state verifier (`verify-capture`): `tick 1247 (perk.choices._len expected=7 actual=5)`

### Key Findings

- New capture SHA family; no prior session entry for `25ef6718`.
- Loader health check after schema compatibility fix:
  - `capture_format_version=3`,
  - `ticks=7260` (`tick 0..7259`, gameplay frame `1..7260`).
- Baseline mismatch profile:
  - `divergence-report` and `bisect-divergence` agree on first sustained drift at `tick 570`,
  - run summary context at focus includes same-tick weapon pickup and assign (`Pistol -> Ion Minigun`).
- Telemetry quality is strong for this artifact:
  - `key_rows=7260`,
  - `key_rows_with_any_signal=7217`,
  - `perk_apply_in_tick_entries=0`,
  - `perk_apply_outside_calls=8`,
  - `config_aim_schemes` and `input_approx.aim_scheme` both present for all ticks.
- `focus-trace --tick 570` shows RNG values align (`capture_calls=36`, `rewrite_calls=36`, `prefix_match=36`), while `divergence-report` still reports `rand_calls(e/a)=36/0` at the same tick and marks `rng_stream_mismatch`.
  - This indicates an accounting/attribution mismatch in divergence reporting around `world_step_tail` rather than a direct replay RNG-value mismatch at the focus tick.
- Capture compatibility gap discovered and fixed:
  - new telemetry field `player_fire` appears under both `tick.checkpoint.debug` and `tick.diagnostics`,
  - loader previously rejected the capture as unknown-field despite format version match.

### Landed Changes

- Updated capture schema compatibility:
  - `src/crimson/original/schema.py`
    - added `player_fire: dict[str, object] | None` to `CaptureCheckpointDebug`,
    - added `player_fire: dict[str, object] | None` to `CaptureDiagnostics`.
- Added regression coverage:
  - `tests/test_original_capture_conversion.py`
    - `test_load_capture_accepts_player_fire_debug_payloads`.
- Added triage artifacts:
  - `analysis/frida/reports/capture_25ef6718_baseline.json`
  - `analysis/frida/reports/capture_25ef6718_baseline_nocache.json`
  - `analysis/frida/reports/capture_25ef6718_bisect.json`
  - `analysis/frida/reports/capture_25ef6718_focus_570.json`

### Validation

- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_25ef6718_baseline.json` *(expected non-zero exit while diverged)*
- `uv run crimson original bisect-divergence artifacts/frida/share/gameplay_diff_capture.json.gz --window-before 12 --window-after 6 --json-out analysis/frida/reports/capture_25ef6718_bisect.json` *(expected non-zero exit while diverged)*
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 570 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_25ef6718_focus_570.json`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/capture_25ef6718_baseline_nocache.json` *(expected non-zero exit while diverged)*
- `uv run pytest tests/test_original_capture_conversion.py -k player_fire_debug_payloads`
- `uv run ruff check src/crimson/original/schema.py tests/test_original_capture_conversion.py`

### Outcome / Next Probe

- Capture loading is now compatible with current `player_fire` telemetry.
- The remaining actionable lead on this SHA is divergence-report RNG accounting at `tick 570`:
  - compare divergence-report’s per-stage rand-call attribution against focus-trace accounting at the same tick,
  - prioritize `src/crimson/original/divergence_report.py` handling of `world_step_tail` rand draws for parity diagnostics correctness before gameplay/runtime patches.

---

