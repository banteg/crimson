---
tags:
  - frida
  - differential-sessions
---

## Session 19 (2026-02-24)

- **Capture:** `/Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst`
- **Capture SHA256:** `fd151c5e063ea3b1419643a1df3fa6439b523fde3a082fc93b51038b93a4fabe`
- **Baseline verifier command:**
  `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/session19/quest_1_8_baseline_nocache.json --no-cache`
- **First mismatch progression:**
  - baseline: `tick 75 (rng_stream_mismatch; rng.tail_shortfall; missing_tail=1)`
  - bisect: `first_bad_tick=75` (`rng_stream_mismatch`)

### Key Findings

- This capture did **not** clear; both baseline and bisect agree on a very early RNG frontier (`tick 75`).
- Focus trace at tick `75` confirms a one-draw native tail shortfall:
  - `capture_calls=81`, `rewrite_calls=80`, `prefix_match=80`, `missing_native_tail=1`
  - missing native caller id is `0x0043d4bd` (currently unmapped in focus output).
- Rewrite RNG callsite distribution at the focus tick is dominated by blood/decal paths:
  - `src/crimson/effects.py:add_random` (`x48` across lines `498..501`)
  - `src/crimson/effects.py:spawn_blood_splatter` (`x20` across lines `790..799`)
  - `src/crimson/sim/presentation_step.py:queue_projectile_decals_post_hit` (`x3`)
- Divergence-report lead attribution is consistent with a missing RNG-consuming branch around projectile-hit/death FX on this early kill event.

### Landed Changes

- None (triage/session-bookkeeping only).

### Validation

- `uv run crimson original capture-health /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst`
  - `result=ok` (loader/telemetry gate passed; `ticks_total=992`).
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/session19/quest_1_8_baseline_nocache.json --no-cache`
  - `result=diverged kind=rng_stream_mismatch tick=75`.
- `uv run crimson original bisect-divergence /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst --window-before 12 --window-after 6 --json-out analysis/frida/reports/session19/quest_1_8_bisect_nocache.json --no-cache`
  - `result=diverged first_bad_tick=75 kind=rng_stream_mismatch`.
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst --tick 75 --near-miss-threshold 0.35 --top-rng 10 --near-miss-limit 8 --diff-limit 8 --no-cache --json-out analysis/frida/reports/session19/quest_1_8_focus_75_nocache.json`
  - `missing_native_tail=1` at caller `0x0043d4bd`.

### Outcome / Next Probe

- Session 19 started because the capture did not clear.
- Next probe should map caller `0x0043d4bd` to a concrete native path and reconcile the missing single RNG draw before/inside the early projectile-hit death FX branch.

### Session 19 (continued: quest_1_8 clear)

- **First mismatch progression (after fixes):**
  - `tick 75 (rng_stream_mismatch; missing_tail=1)`
  - `tick 188 (rng_stream_mismatch; value-stream; pre-focus tick 187 had +78 rewrite tail draws)`
  - `tick 300 (state_mismatch: creature_count + perk.choices ordering skew)`
  - **cleared**: `result=ok` (no divergence in search range)

### Key Findings

- Native caller `0x0043d4bd` resolves to `sfx_play_exclusive` path and consumes one RNG draw when first-hit game tune triggers.
- Remaining `tick 188` RNG drift came from creature slot-32 heading branch skew near `tau` boundary in `angle_approach`; this produced an extra projectile hit at tick 187 and consumed extra decal/blood RNG.
- `tick 300` non-RNG mismatch was ordering-only:
  - capture consumed quest spawn RNG before perk menu RNG on that tick,
  - replay event partition was running deferred `PerkMenuOpenEvent` before deferred capture spawn hooks.

### Landed Changes

- `src/crimson/sim/presentation_step.py`
  - consumed one RNG draw on first-hit game-tune trigger (native `sfx_play_exclusive` parity).
- `src/crimson/sim/sessions.py`
  - added persistent `game_tune_started` state to `QuestDeterministicSession` and threaded it into `StepPipelineOptions`.
- `src/crimson/modes/quest_mode.py`
  - stopped hardcoding `game_tune_started=False`; now uses session state.
- `src/crimson/modes/replay_playback_mode.py`
  - mirrored quest replay path to use session `game_tune_started`.
- `src/crimson/creatures/runtime.py`
  - tightened `_angle_approach` to native-like float32 spill behavior on intermediates/returns.
- `src/crimson/sim/driver/replay_events.py`
  - in deferred original-capture partitioning, now orders post-step events as:
    `state_transition -> capture_spawn -> perk_menu_open`.
- Tests:
  - `tests/test_presentation_step.py`
  - `tests/test_death_timing.py`
  - `tests/test_creature_runtime.py`
  - `tests/test_replay_perk_menu_open_event.py`

### Validation

- `uv run pytest tests/test_creature_runtime.py tests/test_presentation_step.py tests/test_death_timing.py tests/test_quest_deterministic_session.py tests/test_replay_playback_mode_audio.py tests/test_replay_playback_mode_timing.py tests/test_quest_mode_spawns.py`
  - `80 passed`.
- `uv run pytest tests/test_replay_perk_menu_open_event.py tests/test_replay_runners_quest.py`
  - `20 passed`.
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/session19/quest_1_8_after_rngfix3_baseline_nocache.json --no-cache`
  - `result=ok`.
- `uv run crimson original bisect-divergence /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst --window-before 12 --window-after 6 --json-out analysis/frida/reports/session19/quest_1_8_after_rngfix3_bisect_nocache.json --no-cache`
  - `result=ok`.
- `uv run crimson original verify-capture /Users/banteg/syncthing/frida/gameplay_diff_capture.quest_1_8.msgpack.zst --float-abs-tol 1e-3 --max-field-diffs 32`
  - `ok: 992 checkpoints match`.

### Outcome / Next Probe

- `quest_1_8` now clears end-to-end on this branch.
- Next recapture can proceed; Session 19 remains the capture-clear record for SHA `fd151c5e063ea3b1419643a1df3fa6439b523fde3a082fc93b51038b93a4fabe`.
