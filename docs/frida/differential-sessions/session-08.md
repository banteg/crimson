---
tags:
  - frida
  - differential-sessions
---

## Session 8 (2026-02-11)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `6ee322a6c1ac765b343bcdbafa88ad9b92a98ea68c0106490d5dbb719f5325fc`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_6ee322a6_baseline_after_rebase.json`
- **First mismatch:** `tick 22 (players[0].pos.x, players[0].pos.y)`

### Key Findings

- `feat/diff-8` was rebased to latest `origin/master` (`7e5fbc72`) before triage; mismatch profile stayed unchanged (`tick 22` movement drift).
- Divergence is pre-combat and deterministic:
  - `verify-capture` fails at `tick 22`,
  - run result remains `score_xp=0`, `kills=0` through full run.
- Capture input telemetry is partial/legacy relative to strict replay expectations:
  - `input_keys_full_rows=0`, `input_keys_partial_rows=4241`,
  - `move_mode_non_null=0`, `aim_scheme_non_null=0`.
- Focus tick `22` reproduces the stale-input signature:
  - key snapshot reports `move_backward_pressed=true`, `turn_left_pressed=true`,
  - `input_approx` shows large raw movement deltas while `moving=false`,
  - strict key-driven replay diverges immediately on player position.

### Landed Changes

- No gameplay/runtime code changes landed in this session.
- Added rebase-synced triage artifacts:
  - `analysis/frida/reports/capture_6ee322a6_baseline_after_rebase.json`
  - `analysis/frida/reports/capture_6ee322a6_bisect_after_rebase.json`
  - `analysis/frida/reports/capture_6ee322a6_focus_22_after_rebase.json`

### Validation

- `git fetch origin --prune`
- `git rebase origin/master`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_6ee322a6_baseline_after_rebase.json` *(expected non-zero exit while diverged)*
- `uv run crimson original bisect-divergence artifacts/frida/share/gameplay_diff_capture.json.gz --window-before 12 --window-after 6 --json-out analysis/frida/reports/capture_6ee322a6_bisect_after_rebase.json` *(expected non-zero exit while diverged)*
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 22 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_6ee322a6_focus_22_after_rebase.json`

### Outcome / Next Probe

- This SHA family is stale against current strict replay assumptions and should be treated as non-actionable for gameplay parity patches.
- Capture a new `gameplay_diff_capture` artifact with the current Frida script (post-`grim_is_key_down`/strict-input changes), then start a new session keyed by the new SHA.

---

