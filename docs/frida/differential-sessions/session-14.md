---
tags:
  - frida
  - differential-sessions
---

## Session 14 (2026-02-13)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `49aec5d3705f7c8cfb90143a6d204053c8ba6744ca30c4a367666cdaec04fe0e`
- **First mismatch progression:**
  - sustained (`divergence-report` + `bisect-divergence`): `tick 1390 (rng_stream_mismatch)`
  - checkpoint-state verifier (`verify-capture`): `tick 1571 (players[0].experience/score_xp expected=10406 actual=10450)`

### Key Findings

- New capture SHA family; no prior session entry for `49aec5d3`.
- Loader health check passed:
  - `capture_format_version=3`,
  - `ticks=9463` (`tick 0..9462`, gameplay frame `1..9463`).
- Baseline run context before first sustained drift includes:
  - `perk_pick` `Evil Eyes (11)` at `tick 1318`,
  - first sustained mismatch at `tick 1390` with `rand_calls(e/a)=1/0`.
- `focus-trace --tick 1390` confirms RNG-tail shortfall at focus:
  - `capture_calls=1`, `rewrite_calls=0`, `missing_native_tail=1`,
  - missing call caller top: `0x004263b1 x1`.
- `divergence-report` investigation leads attribute the pre-focus shortfall to a missing RNG-consuming branch in `creature_update_all` path.
- Telemetry quality gate is strong for this artifact:
  - `key_rows=9463`, `key_rows_with_any_signal=9450`,
  - `perk_apply_in_tick_entries=0`, `perk_apply_outside_calls=13`,
  - `sample_creature_rows=415067`, `sample_creature_rows_with_ai_lineage=415067`,
  - `creature_lifecycle_rows=3145`, `creature_lifecycle_rows_with_ai_lineage=3145`.

### Landed Changes

- None (triage/session-bookkeeping only).

### Validation

- `uv run python - <<'PY' ... load_capture(Path("artifacts/frida/share/gameplay_diff_capture.json.gz")) ...` (health check: sha/version/tick range)
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_49aec5d3_baseline.json` *(expected non-zero exit while diverged)*
- `uv run crimson original bisect-divergence artifacts/frida/share/gameplay_diff_capture.json.gz --window-before 12 --window-after 6 --json-out analysis/frida/reports/capture_49aec5d3_bisect.json` *(expected non-zero exit while diverged)*
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 1390 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_49aec5d3_focus_1390.json`
- `uv run python - <<'PY' ... telemetry quality audit ...` (key/perk + AI-lineage coverage)

### Outcome / Next Probe

- Primary actionable lead is the first RNG-tail shortfall at `tick 1390` (`caller_static=0x004263b1`, mapped in divergence lead as `creature_update_all` path).
- Next probe should focus on replay/runtime branch parity in creature/projectile update flow around `tick 1390`, especially:
  - `src/crimson/creatures/runtime.py`
  - `src/crimson/creatures/ai.py`
  - `src/crimson/projectiles/pools.py`
  - `src/crimson/effects.py`

### Session 14 (continued: update 2)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `49aec5d3705f7c8cfb90143a6d204053c8ba6744ca30c4a367666cdaec04fe0e`
- **First mismatch progression:**
  - pre-fix baseline (`3804bbf6`): `tick 5226 (rng_stream_mismatch, native 16-call survival spawn burst arrived one tick earlier than rewrite)`
  - after landed fix in this session: `tick 5305 (state_mismatch: bonus_timers.9 expected=81 actual=82)`

### Key Findings

- Confirmed prior `tick 5226` parity issue was a one-tick delayed survival wave spawn in rewrite:
  - native burst at `5226`, rewrite at `5227`,
  - callers/callsites map to `survival_spawn_creature` path.
- Fixing survival-session scaled ms derivation (for original-capture replay with dt overrides) realigned the spawn burst:
  - `focus-trace --tick 5226`: `capture_calls=16`, `rewrite_calls=16`, `prefix_match=16`,
  - `focus-trace --tick 5227`: `capture_calls=0`, `rewrite_calls=0`.
- New first mismatch is a transient one-tick Reflex Boost timer rounding drift:
  - `tick 5305`: `bonus_timers.9 expected=81 actual=82`,
  - self-heals on the next tick (`tick 5306`).
- Failed local probes (not landed):
  - applying the same scaled-ms conversion change in `run_deterministic_step` (no net gain),
  - hybrid `<1.0s` fallback in survival session (reintroduced one-tick RNG spawn shift at `5307/5308`).
- Current working hypothesis for residual timer drift:
  - native `player_update` temporarily mutates global `frame_dt` and restores it with `*1.6666666`, introducing tiny float drift before `bonus_reflex_boost_timer` decrement,
  - rewrite currently models movement dt locally and does not propagate this global post-player-update drift.

### Landed Changes

- `src/crimson/sim/sessions.py`
  - In `SurvivalDeterministicSession.step_tick`, when capture `dt_frame_ms_i32` is present and Reflex Boost scaling is active, derive session ms counters from scaled float dt (`int(dt_sim * 1000.0)`) instead of integer-base ms scaling.
  - This matches native survival wave cadence in the `tick 5226` window.
- `tests/test_replay_runners.py`
  - Added `test_survival_runner_original_capture_reflex_scaled_dt_ms_uses_scaled_float_dt` to lock the scaled-float ms behavior for original-capture replay under Reflex Boost time scaling.

### Validation

- `uv run pytest tests/test_replay_runners.py -q`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix13c_sessions_only_baseline_nocache.json` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 5226 --near-miss-threshold 0.35 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix13b_focus_5226_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 5227 --near-miss-threshold 0.35 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix13b_focus_5227_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 5305 --near-miss-threshold 0.35 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix13b_focus_5305_nocache.json`

### Outcome / Next Probe

- Landed fix removed the dominant `tick 5226` RNG-stream drift and advanced first mismatch to a narrow one-tick timer rounding discrepancy.
- Next probe should target native `frame_dt` round-trip side effects in `player_update` and post-player-update timer decrement ordering:
  - `player_update` at `0x004136b0` (`frame_dt` temporary rescale/restore),
  - `src/crimson/gameplay.py`,
  - `src/crimson/sim/world_state.py`.

### Session 14 (continued: update 3)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `49aec5d3705f7c8cfb90143a6d204053c8ba6744ca30c4a367666cdaec04fe0e`
- **First mismatch progression:**
  - pre-fix baseline (`fix38`): `tick 8999 (rng_stream_mismatch, missing_native_tail=16)`
  - after landed fix in this session: `tick 9065 (state_mismatch: players[0].experience/score_xp +110 in replay)`

### Key Findings

- A tiny Reflex Boost tail-rounding bias remained upstream of the old `tick 8999` RNG shortfall.
  - At `tick 8915`, capture and replay quest cadence differed by one ms (`capture +21` vs `rewrite +20`).
  - Bias sweep around `_REFLEX_TIMER_SUBTRACT_BIAS` showed `4e-9/5e-9/1e-8` all remove that cadence mismatch and eliminate the `tick 8999` RNG-tail shortfall.
- With the Reflex timer fix in place, first sustained divergence moved to `tick 9065` and became XP-only (`+110` replay).
  - `focus-trace` at `9065` shows replay-only Splitter branch (`proj 17` hit creature `17`, spawning children `idx 9/11`) while capture shows five misses for `proj 17`.
- Root-cause chain for the `9065` branch was traced backward through spawn ancestry:
  - `9065`: `proj 17` replay hit vs capture miss,
  - `9043`: same slot hits one query earlier in replay, creating translated child spawn positions,
  - `9041`/`9030`: translated Splitter-hit spawn positions persist across generations,
  - `9014`: parent `proj 4` hit timing differs because target creature `31` position is already far from capture (`~+6.39,+1.50` in replay at the decisive query),
  - `9013`: initial player projectile spawn for this chain is near-identical to capture (drift is not introduced at fire spawn).
- This isolates the remaining failure as upstream creature-motion/AI parity drift, not a local Splitter branch implementation bug.

### Landed Changes

- `src/crimson/bonuses/update.py`
  - tuned `_REFLEX_TIMER_SUBTRACT_BIAS` from `2e-9` to `4e-9` to match native Reflex tail decrement cadence in this capture family.

### Validation

- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix38_try_reflex_bias_4e-9_baseline_nocache.json` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 8915 --near-miss-threshold 0.35 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix38_focus_8915_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 9065 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix39_focus_9065_nm20_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 9043 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix39_focus_9043_nm20_nocache.json`

### Outcome / Next Probe

- Reflex-tail parity improvement is landed and moved divergence later (`8999 -> 9065`), but the remaining blocker is upstream creature-motion drift causing earlier/later hit resolution in long Splitter chains.
- Current capture is insufficient to localize the first creature-motion branch split in replay with confidence from existing per-tick summaries alone.
- Next probe should add creature update micro-tracing for focused ticks (movement candidate selection + per-step target heading/obstacle decisions) and recapture:
  - native `creature_update` movement branch decisions,
  - rewrite `src/crimson/creatures/runtime.py` + `src/crimson/creatures/ai.py` parity at the first ancestry tick where creature position drift appears.

### Session 14 (continued: update 4)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `49aec5d3705f7c8cfb90143a6d204053c8ba6744ca30c4a367666cdaec04fe0e`
- **First mismatch progression:**
  - baseline after Session 14 update 3 fix (`0974bf4d`): `tick 9065 (state_mismatch: players[0].experience/score_xp +110 in replay)`
  - no additional gameplay fix landed in this session (investigation-only)

### Key Findings

- Reconfirmed the current baseline drift point:
  - `divergence-report --no-cache` remains `tick 9065`,
  - replay still produces a replay-only kill/XP branch (`+110`).
- Focus ancestry checkpoints (`9013/9014`) again show slot `31` as the parent-target divergence source for the later Splitter chain.
- A sequential `_FocusRuntime` scan (same engine used by `focus-trace`) localized the slot-31 drift timeline:
  - respawn lifecycle for slot `31` (type `4`) occurs at `tick 8679` (`source=survival_spawn_creature`),
  - first measurable spatial delta appears at `tick 8736` (`x_delta=-0.000061`),
  - drift grows smoothly through chase updates (`x_delta +0.523 @8957`, `+1.032 @8964`, `+2.063 @8974`, `+6.002 @8993`),
  - first large HP branch split appears later at `tick 9011` (`hp_delta=-125.294`), then feeds the known `9014 -> 9043 -> 9065` chain.
- Slot-31 behavior in the onset window is not an orbit-branch issue:
  - rewrite `force_target=1` through the early drift window (`~8890..8974`), so movement is player-chase steering in those ticks.
- Decompile + structural queries were used to re-check native movement/turn paths:
  - `creature_update_all` (`0x00426220`) and `angle_approach` (`0x0041f430`) loops/conditions,
  - `survival_spawn_creature` confirms spawn writes heading/velocity/move_speed but leaves other fields as recycled-slot state.
- Multiple targeted A/B probes were run via runtime monkeypatches with no material improvement on the slot-31 drift profile:
  - orbit helper intermediate-rounding changes,
  - distance helper rounding changes,
  - stricter float32 arithmetic variants in `angle_approach`,
  - `heading_from_delta_f32` f32-cast input deltas,
  - dt resolve f32-cast,
  - spawn/init scalar f32 canonicalization in `_apply_init`.
- Conclusion: we can localize the drift timeline from current capture, but not disambiguate the first causative arithmetic/branch delta in native without finer-grained creature-update internals.

### Landed Changes

- None (investigation/session-bookkeeping only).

### Validation

- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix40_baseline_nocache.json` *(expected non-zero exit while diverged)*
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 9013 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix40_focus_9013_nm20_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 9014 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix40_focus_9014_nm20_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 8957 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix40_focus_8957_nm20_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 8964 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix40_focus_8964_nm20_nocache.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json.gz --tick 8974 --near-miss-threshold 20 --no-cache --json-out analysis/frida/reports/capture_49aec5d3_fix40_focus_8974_nm20_nocache.json`
- `uv run python - <<'PY' ... _FocusRuntime slot-31 drift scan over ancestry ticks ...` (onset localization + heading/target deltas + force_target inspection)
- Historical structural scan over the then-current Ghidra view, covering
  `angle_approach` and movement-loop forms; refresh those functions by address
  through `just analysis-function`.

### Outcome / Next Probe

- **Hard block with current capture granularity:** first visible slot-31 drift is sub-ULP-scale and accumulative (`8736+`), but current telemetry lacks per-creature pre/post movement internals to isolate which native arithmetic/branch diverges first.
- Next required capture probe should add creature-update micro-telemetry for targeted slots/ticks:
  - per-creature pre/post `heading`, `target_heading`, `force_target`, `ai_mode`, `move_scale`,
  - per-creature `angle_approach` inputs/step outputs (`angle`, `target`, `rate`, chosen branch),
  - raw `target_x/target_y` and `dist_to_target` comparisons used by `<40` / `>400` forcing,
  - emitted at least for slot `31` around `8679..9014` and the player-chase onset window (`8730..8900`).

---
