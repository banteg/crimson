---
tags:
  - frida
  - differential-sessions
---

## Session 9 (2026-02-11)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `8e510e013157b89731b2d2f415dad4f286746264e274cb20e6b12da3107359ed`
- **Baseline verifier command:**
  `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32`
- **First mismatch progression:**
  - initial: `tick 833 (players[0].experience, score_xp)`
  - after fire synthesis fixes: `tick 2111 (players[0].ammo)`
  - after secondary-spawn synthesis: `tick 3251 (players[0].ammo)`
  - after cooldown float32 snap: `tick 3613 (players[0].experience, score_xp)`
  - after secondary seeker target-at-spawn parity: `tick 4227 (players[0].experience, score_xp)`

### Key Findings

- This capture family has partial input/config telemetry:
  - `input_approx.aim_scheme` is always `null`,
  - snapshot `config_aim_schemes` is absent,
  - `input_player_keys.fire_down/fire_pressed` is often `null`/`false`,
  - `fired_events` is always `0`.
- The run is known to use sidecar-configured `config_aim_schemes=5` (Computer), but that value is not encoded in this artifact.
- At the current frontier (`tick 4227`), rewrite awards one extra kill (`+40 XP`):
  - native capture debug at XP-onset shows one death (`creature_index=21`, `xp_awarded=43`),
  - rewrite at the same tick reports two deaths (`idx=52 xp=40`, `idx=21 xp=43`).
- Instrumented replay shows the extra death (`idx=52`) comes from Ion Rifle linger AoE (`_linger_ion_rifle`) in rewrite.
- Projectile trajectory probe around ticks `4208-4227` shows the triggering Ion projectile is spawned with a small angle drift (`capture=0.380889982`, `rewrite=0.392519916`), then resolves hit/linger one tick earlier in rewrite (`4222` vs `4223`), causing the later extra kill.
- Remaining mismatch around that window is now dominated by capture-side RNG/event attribution instability:
  - `divergence-report` window rows show per-tick RNG/event splits around the same projectile window that are internally inconsistent (`tick 4222 expected_rand_calls=3 vs actual=105`, `tick 4223 expected_rand_calls=92 vs actual=0`),
  - capture reports `expected_rand_calls=0` on ticks where rewrite takes deterministic AI7 timer draws (`4218`, `4219`), with no capture-side branch attribution to disambiguate correctness.

### Landed Changes

- Added runtime mode-5 gameplay support wiring:
  - `src/crimson/local_input.py`
  - `src/crimson/modes/base_gameplay_mode.py`
  - `tests/test_local_input.py`
  - `tests/test_multiplayer_wiring.py`
- Added capture-script mode telemetry:
  - `scripts/frida/gameplay_diff_capture.js` now emits per-player `config_movement_schemes` and `config_aim_schemes` in globals and `input_approx`.
- Added mode-5 parity in controls UI:
  - `src/crimson/screens/panels/controls_labels.py`
  - `src/crimson/screens/panels/controls.py`
  - mode `5` is displayed when loaded from config, but not offered unless already loaded.
- Added replay/verification override plumbing for telemetry-poor captures:
  - `--aim-scheme-player PLAYER=SCHEME` for `verify-capture`, `convert-capture`, `divergence-report`, `bisect-divergence`, and `focus-trace`.
  - relevant files:
    - `src/crimson/cli.py`
    - `src/crimson/original/capture.py`
    - `src/crimson/original/verify.py`
    - `src/crimson/original/divergence_report.py`
    - `src/crimson/original/divergence_bisect.py`
    - `src/crimson/original/focus_trace.py`
    - `src/crimson/original/__init__.py`
- Hardened synthesis to avoid false fire inference from bonus-only projectile bursts in mode-5 runs (`src/crimson/original/capture.py`, `tests/test_original_capture_conversion.py`).
- Aligned secondary seeker behavior with native spawn-time target acquisition (`fx_spawn_secondary_projectile` parity):
  - `src/crimson/projectiles.py`
  - `src/crimson/gameplay.py`
  - `src/crimson/sim/world_state.py`
  - `src/crimson/views/player.py`
  - `src/crimson/views/projectile_render_debug.py`
  - `tests/test_projectiles.py`
- Tightened projectile step math to float32 store boundaries in parity-critical update paths (`src/crimson/projectiles.py`).
- Commit: `ab992f4a` (`fix(projectiles): align secondary targeting and f32 stepping`).

### Validation

- `just check`
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32` *(expected non-zero exit while diverged)*
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32 --aim-scheme-player 0=5` *(expected non-zero exit while diverged)*
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --max-ticks 400 --aim-scheme-player 0=5 --window 8 --run-summary-short --run-summary-short-max-rows 5` *(expected non-zero exit while diverged)*
- `uv run pytest tests/test_projectiles.py`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 4227 --aim-scheme-player 0=5 --json-out analysis/frida/reports/capture_8e510e01_focus_4227_after_secondary_spawn_target_fix.json`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32 --aim-scheme-player 0=5 --focus-tick 4227 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 8 --run-summary-short-max-rows 80 --json-out analysis/frida/reports/capture_8e510e01_divergence_focus_4227_after_secondary_spawn_target_fix.json` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 4208 --aim-scheme-player 0=5 --json-out analysis/frida/reports/capture_8e510e01_focus_4208_after_secondary_spawn_target_fix.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 4218 --aim-scheme-player 0=5 --json-out analysis/frida/reports/capture_8e510e01_focus_4218_after_secondary_spawn_target_fix.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 4219 --aim-scheme-player 0=5 --json-out analysis/frida/reports/capture_8e510e01_focus_4219_after_secondary_spawn_target_fix.json`

### Outcome / Next Probe

- Blocked on this SHA by insufficient/incorrect capture data for the remaining root cause near `ticks 4222-4227`:
  - native-vs-rewrite RNG/event attribution in the capture is not stable enough around the critical Ion shot window to prove whether remaining call-order drift is rewrite logic or capture-side tick accounting.
- Next probe requires a new `gameplay_diff_capture` recording with current script telemetry and then repeating:
  - `verify-capture --aim-scheme-player 0=5`,
  - `divergence-report --run-summary-focus-context`,
  - `focus-trace` across the first post-4227 divergence window.
---

