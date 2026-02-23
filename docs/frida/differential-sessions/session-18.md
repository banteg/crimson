---
tags:
  - frida
  - differential-sessions
---

## Session 18 (2026-02-19)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_6.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_quest_gz_post_master_rebase`)
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_6.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix: `tick 5384 (rng_stream_mismatch)` with downstream one-tick projectile hit timing slip at `5386/5387`
  - after this fix: `ok (no divergence found with current settings)`

### Key Findings

- The `5384` RNG drift was caused by rewrite-only RNG work on `tick 5383`, not by the `5384` fire path itself:
  - focus trace before fix: `tick 5383 capture/rewrite calls = 100/102` with full value-prefix match,
  - rewrite consumed two extra values (`14154`, `19675`), shifting all `tick 5384` weapon-fire rolls.
- The extra draws came from world-level death-SFX planning for plague-timer kills:
  - plague kill path in `creatures.runtime` already consumes native contact-SFX RNG,
  - `world_state.step` additionally ran `plan_death_sfx_keys` for those same deaths, adding two rewrite-only draws.
- After skipping world death-SFX planning for plague deaths:
  - `focus-trace` realigned at both `tick 5383` and `tick 5384` (`prefix_match = capture_calls`),
  - `quest_1_6` baseline report went fully clean.

### Landed Changes

- `src/crimson/creatures/runtime.py`
  - added `CreatureDeath.plan_death_sfx: bool = True`,
  - threaded `plan_death_sfx` through `handle_death`,
  - set `plan_death_sfx=False` for plague timer kills.
- `src/crimson/sim/world_state.py`
  - `_plan_death_sfx_now(...)` now skips deaths with `plan_death_sfx=False`.
- Tests:
  - `tests/test_plaguebearer_perk.py` now asserts plague kills mark `plan_death_sfx=False`,
  - `tests/test_death_timing.py` adds `test_plague_kill_death_event_skips_world_death_sfx_planning`.

### Validation

- Targeted tests:
  - `uv run pytest tests/test_plaguebearer_perk.py::test_plaguebearer_infection_kill_increments_global_count tests/test_death_timing.py::test_plague_kill_death_event_skips_world_death_sfx_planning tests/test_death_timing.py::test_death_sfx_rand_consumes_past_cap tests/test_death_timing.py::test_detonation_followup_does_not_double_plan_death_sfx`
- Focus traces:
  - `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.quest_1_6.json.gz --tick 5383 --near-miss-threshold 0.35 --no-cache --json-out analysis/frida/reports/session18_quest_gz_post_master_rebase/gameplay_diff_capture.quest_1_6_focus_5383_after_plague_sfx_fix_nocache.json`
  - `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.quest_1_6.json.gz --tick 5384 --near-miss-threshold 0.35 --no-cache --json-out analysis/frida/reports/session18_quest_gz_post_master_rebase/gameplay_diff_capture.quest_1_6_focus_5384_after_plague_sfx_fix_nocache.json`
- Baseline recheck:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_6.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache` → `result=ok (no divergence found with current settings)`
- Repository checks:
  - `just check`

### Outcome / Next Probe

- `quest_1_6` in this post-rebase capture family is clean again.
- Continue the remaining quest split frontier from the earliest unresolved file/tick in the current sweep.

## Session 18 (continued: strict projectile radius boundary)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_quest_gz_followup`)
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix: `tick 7655` (`players[0].experience`, `score_xp`, creature-count drift)
  - after this fix: `tick 7722` (`players[0].experience`, `score_xp`, creature-count drift)

### Key Findings

- Focus tracing at the previous frontier showed a rewrite-only projectile hit accepted with positive margin (`+0.000928`) by `_within_native_find_radius(...)`.
- The acceptance was caused by a local positive epsilon (`0.001`) that allowed near-edge non-native hits.
- That rewrite-only hit/death path created an immediate XP/score overcount and pushed subsequent RNG/collision timing off the native track.

### Landed Changes

- `src/crimson/projectiles/runtime/collision.py`
  - set `_NATIVE_FIND_RADIUS_MARGIN_EPS` to `0.0`,
  - kept strict native boundary semantics for hit acceptance.
- `tests/test_projectiles.py`
  - added `test_within_native_find_radius_uses_strict_boundary` to lock the regression case where a tiny positive over-margin must not count as a hit.

### Validation

- Targeted tests:
  - `uv run pytest tests/test_projectiles.py`
- Repository checks:
  - `just check`
- Divergence rechecks:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
    - `result=diverged kind=state_mismatch tick=7722`
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_3_2.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
    - `result=ok (no divergence found with current settings)`

### Outcome / Next Probe

- This fix cleared `quest_3_2` and moved the earliest unresolved frontier later in `quest_1_8` (`7655 -> 7722`).
- Next probe should focus `quest_1_8` at `tick 7722` and isolate the first rewrite-only kill/death branch now driving creature-count and XP drift.

## Session 18 (continued: Fire Cough pre-move spawn origin parity)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_9.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_quest_gz_after_unlink_sweep`)
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_9.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix: `tick 9259` (`rng.value_stream_mismatch`)
  - after this fix: `tick 9482` (`rng.value_stream_mismatch`)

### Key Findings

- `quest_1_9` showed a rewrite-only RNG burst at `tick 9257` (`+68` draws) with one extra projectile hit (`capture=6`, `rewrite=7`), then first value-stream mismatch at `tick 9259`.
- Focus traces localized the first projectile trajectory split to projectile `idx=2` at `tick 9254`, with rewrite projectile position offset by about `(+1.923, +1.923)`.
- That offset exactly matched the player movement delta in the same tick, proving rewrite spawned the Fire Cough projectile from post-move player position while native capture spawned from pre-move position.

### Landed Changes

- `src/crimson/perks/impl/fire_cough.py`
  - switched Fire Cough projectile origin math to `ctx.player_pos_before_move` for:
    - muzzle position,
    - spread-distance basis,
    - jitter-to-angle vector.
- `tests/test_player_update.py`
  - added `test_player_update_fire_cough_uses_pre_move_position_for_spawn` regression to lock moving-frame pre-move spawn semantics.

### Validation

- Targeted tests:
  - `uv run pytest tests/test_player_update.py -k "fire_cough"`
- Divergence recheck:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_9.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_alt_leads/quest_1_9_after_fire_cough_pre_move_fix.json`
    - `result=diverged kind=rng_stream_mismatch tick=9482` (frontier moved later from `9259`)
- Spot checks on unrelated fronts remained stable:
  - `quest_1_10` remains at `tick 10018` (`rng.projectile_hit_resolution_shortfall`)
  - `quest_2_1` remains at `tick 11417` (`rng.value_stream_mismatch`)
  - `quest_4_5` remains at `tick 46214` (`rng.value_stream_mismatch`)

### Outcome / Next Probe

- Fire Cough pre-move spawn parity removed the early `quest_1_9` branch split and pushed the first sustained mismatch significantly later (`9259 -> 9482`).
- Next probe should focus `quest_1_9` at `tick 9482`, where first mismatch now maps to native `player_update` RNG callers (`0x00415a6d` cluster), to identify the next branch-order/source-of-draw divergence.

## Session 18 (continued: ranged-shock lethal death branch parity)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_10.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_alt_leads`)
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_10.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix set: `tick 10018` (`rng.projectile_hit_resolution_shortfall`, missing tail `20`)
  - after lethal burst branch only: `tick 10018` (state mismatch with RNG overrun `+1`)
  - after death-SFX suppression for this path: `tick 10018` (state mismatch; focus RNG stream aligned `328/328`)

### Key Findings

- Native `creature_apply_damage` has a lethal branch for `flags & 0x10` that consumes 20 RNG draws (5 iterations x 4 draws) and spawns burst effects instead of random death-SFX selection.
- Rewrite was missing that lethal burst branch, then after adding it still consumed one extra RNG draw due world-level death-SFX planning on the same death.
- Suppressing death-SFX planning for lethal kills of `RANGED_ATTACK_SHOCK` creatures removed the extra RNG draw and restored focus-tick RNG alignment.

### Landed Changes

- `src/crimson/creatures/damage.py`
  - added lethal `RANGED_ATTACK_SHOCK` burst path to mirror native RNG/effect semantics,
  - threaded optional effect context through damage helpers.
- `src/crimson/sim/world_state.py`
  - pass effect context into projectile damage apply path,
  - suppress death-SFX planning on lethal `RANGED_ATTACK_SHOCK` damage follow-up,
  - forward `plan_death_sfx` into `handle_death(...)`.
- `src/crimson/creatures/runtime.py`
  - pass effect context into lethal-followup callsites,
  - suppress death-SFX planning for lethal `RANGED_ATTACK_SHOCK` callback deaths.
- `src/crimson/perks/impl/final_revenge.py`
  - pass effect context into lethal-followup callsite,
  - suppress death-SFX planning for lethal `RANGED_ATTACK_SHOCK` callback deaths.
- `tests/test_death_timing.py`
  - added regression `test_ranged_shock_lethal_skips_world_death_sfx_planning`.

### Validation

- Targeted checks:
  - `uv run pytest tests/test_creature_damage.py tests/test_creature_damage_callsite_guardrails.py tests/test_projectile_hit_effects.py tests/test_death_timing.py -q`
- Repository checks:
  - `just check`
- Divergence rechecks:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_10.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_alt_leads/quest_1_10_after_ranged_shock_lethal_burst_fix_nocache.json`
    - `result=diverged kind=state_mismatch tick=10018` with focus RNG overrun `+1`
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_10.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_alt_leads/quest_1_10_after_ranged_shock_death_sfx_suppression_nocache.json`
    - `result=diverged kind=state_mismatch tick=10018` with focus RNG stream fully aligned (`328/328`, `missing_tail=0`)

### Outcome / Next Probe

- The `quest_1_10` focus RNG shortfall at `tick 10018` is resolved; the remaining mismatch at that tick is now state-only (`perk.pending_count`, `players[0].level`) with aligned RNG stream.
- Next probe should move earlier in this capture to the still-reported projectile-hit-resolution lead (`tick 9757`) and isolate the missing rewrite hit-resolve path.

## Session 18 (continued: quest_1_10 progression pacing and idle-complete reflex parity)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_10.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_alt_leads`)
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_10.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix set: `tick 10018` (state mismatch: `perk.pending_count`, `players[0].level`)
  - after single-step survival level-up pacing: `tick 10477` (`bonus_timers.9`: expected `0`, actual `210`)
  - after quest idle-complete active-slot parity fix: `result=ok (no divergence found with current settings)`

### Key Findings

- Native survival progression advances at most one level threshold per update tick; rewrite looped multiple thresholds in one tick, over-incrementing quest perk pending state.
- Native `creatures_none_active` checks creature slot `active` flags, not `hp > 0`; corpses remain "active" until lifecycle finalization.
- Quest-mode idle-complete reflex clear (`bonus_reflex_boost_timer = 0`) is correct only when native-style active-slot emptiness and empty spawn table are both true.

### Landed Changes

- `src/crimson/gameplay.py`
  - changed `survival_check_level_up` to advance at most one threshold per tick.
- `tests/test_gameplay_progression.py`
  - added `test_survival_level_up_advances_one_threshold_per_tick`.
- `src/crimson/sim/sessions.py`
  - switched quest `creatures_none_active` computation to native active-slot semantics (`creature.active`),
  - preserved quest idle-complete reflex clear and completion-transition gating using the same `spawn_table_empty_now` evaluation.
- `tests/test_quest_deterministic_session.py`
  - added `test_quest_session_clears_reflex_boost_when_quest_is_idle_complete`.

### Validation

- Targeted checks:
  - `uv run pytest tests/test_quest_deterministic_session.py tests/test_reflex_boosted_perk.py tests/test_gameplay_progression.py -q`
- Divergence recheck:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_10.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_alt_leads/quest_1_10_after_idle_complete_reflex_clear_fix_nocache.json`
    - `result=ok (no divergence found with current settings)`
- Repository checks:
  - `just check`

### Outcome / Next Probe

- `quest_1_10` is now cleared and can be unlinked from the active divergence set.
- Remaining unresolved capture fronts should continue from currently outstanding quest files (`quest_1_9`, `quest_2_1`, `quest_4_5` in this family).

## Session 18 (continued: quest_1_9 Fire Cough spread cooldown ordering parity)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_9.json.gz` *(now unlinked after verification)*
- **Capture family:** post-master-rebase quest split set (`session18_alt_leads`)
- **Baseline verifier command (pre-unlink):**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_9.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix: `tick 9482` (`rng_stream_mismatch`)
  - after this fix: `result=ok (no divergence found with current settings)` *(pre-unlink no-cache run)*

### Key Findings

- Fire Cough samples `player.spread_heat` inside perk tick execution.
- Rewrite was decaying spread heat before `apply_player_perk_ticks(...)`; native ordering cools spread after perk ticks/movement while still before weapon fire.
- On the trigger tick in this capture, the sampled spread differed by exactly `dt * 0.4`, which shifted Fire Cough jitter angle enough to flip downstream projectile hit acceptance and RNG tail alignment.

### Landed Changes

- `src/crimson/gameplay.py`
  - moved the spread-heat cooldown block to after perk ticks/aim update and before fire-gate + `_player_fire_weapon(...)`:
    - `Sharpshooter`: clamp to `0.02`,
    - otherwise: `max(0.01, spread_heat - dt * 0.4)`.

### Validation

- Repository checks:
  - `just check`
- Divergence checks:
  - `quest_1_9` (pre-unlink no-cache): `result=ok`.
  - `quest_1_8` remains diverged at `tick 7722` (see `analysis/frida/reports/session18_alt_leads/quest_1_8_after_spread_decay_reorder_nocache.json`).
  - `quest_2_1` remains diverged at `tick 11417` (see `analysis/frida/reports/session18_alt_leads/quest_2_1_after_spread_decay_reorder_nocache.json`).

### Outcome / Next Probe

- `quest_1_9` is cleared and unlinked from `artifacts/frida/share/`.
- Earliest unresolved frontier in this set remains `quest_1_8` at `tick 7722`; continue by isolating the first RNG/value stream fork there.

## Session 18 (continued: `angle_approach` decompile-order parity)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_alt_leads`)
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix: `tick 7722` (`state_mismatch`, progression-timing drift)
  - after this fix: `tick 7756` (`rng_stream_mismatch`, projectile-hit-resolution shortfall)

### Key Findings

- Native `angle_approach` (`0x0041f430`) updates the wrapped heading arc in decompile order and does not enforce extra float32 truncation on intermediate turn-delta arithmetic.
- The rewrite helper had over-quantized turn-step intermediates; this amplified slot-level heading drift before the frontier window and flipped kill timing.
- Moving `_angle_approach(...)` to the decompile-faithful arithmetic order moved two active frontiers later with no earlier regressions in the linked no-cache quest sweep:
  - `quest_1_8`: `7722 -> 7756` (`+34` ticks),
  - `quest_4_5`: `46214 -> 46308` (`+94` ticks; category moved from `rng.value_stream_mismatch` to `rng.tail_shortfall`).

### Landed Changes

- `src/crimson/creatures/runtime.py`
  - rewrote `_angle_approach(...)` to mirror native wrap/direct-vs-wrapped arc selection and step-direction logic in decompile order.

### Validation

- Targeted no-cache rechecks:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_alt_leads_recheck/quest_1_8_nocache_with_angle_probe_v3.json`
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_2_1.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_alt_leads_recheck/quest_2_1_nocache_with_angle_probe_v3.json`
- Full linked-capture no-cache canary sweep summary:
  - `analysis/frida/reports/session18_alt_leads_recheck_angle_v3_nocache/_summary.tsv`
- Repository checks:
  - `just check`

### Outcome / Next Probe

- No linked captures are clean in this pass, so there are no new capture unlinks.
- Earliest unresolved frontier moved to `quest_1_8 tick 7756`; next probe remains projectile-hit/kill-resolution parity at the first missing native tail branch in that window.

## Session 18 (continued: `man_bomb` bootstrap interval inference false-wrap fix)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_2_1.json.gz` *(now unlinked after verification)*
- **Capture family:** post-master-rebase quest split set (`session18_alt_leads`)
- **Baseline verifier command (pre-fix):**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_2_1.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this fix: `tick 11417` (`rng_stream_mismatch`)
  - after this fix: `result=ok (no divergence found with current settings)` *(no-cache run)*

### Key Findings

- Replay bootstrap interval inference treated the first observed active `man_bomb` timer drop as a trigger wrap.
- In this capture, the first drop (`11380 -> 11381`, `1.225 -> 0.0`) was a movement-gated reset, not a trigger wrap; inferred interval became `~1.301s`.
- With that wrong interval, rewrite incorrectly triggered Man Bomb at `tick 11416` (`8` extra RNG calls/projectiles), creating the `tick 11417` RNG stream fork.
- True man-bomb trigger wraps later in the same capture infer `~4.0s`, consistent with native post-trigger behavior.

### Landed Changes

- `src/crimson/original/capture.py`
  - stopped inferring bootstrap `man_bomb` interval from timer drops in `_infer_bootstrap_perk_intervals(...)`;
  - kept inference for `hot_tempered` and `fire_cough`.
- `tests/test_original_capture_conversion.py`
  - added `test_convert_capture_to_replay_bootstrap_payload_does_not_infer_man_bomb_from_timer_drop`.

### Validation

- Targeted tests:
  - `uv run pytest tests/test_original_capture_conversion.py -k "bootstrap_payload_infer or man_bomb_from_timer_drop" -q`
- Divergence recheck:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_2_1.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_alt_leads_continue_pass/quest_2_1_after_bootstrap_interval_fix_nocache.json`
    - `result=ok (no divergence found with current settings)`

### Outcome / Next Probe

- `quest_2_1` is cleared and unlinked from `artifacts/frida/share/`.
- Remaining earliest unresolved frontier in the active set remains `quest_1_8 tick 7756`.

## Session 18 (continued: projectile-hit shortfall owner-collision normalization)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_alt_leads`)
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - before this tooling fix: `tick 7756` (`rng_stream_mismatch`, categorized as `rng.projectile_hit_resolution_shortfall` via pre-focus lead at `tick 7753`)
  - after this tooling fix: `tick 7756` (`rng_stream_mismatch`, categorized as `rng.tail_shortfall`; projectile-hit shortfall lead removed)

### Key Findings

- In this capture family, `projectile_find_hit_count` can include owner-collision query rows; at the old lead tick (`7753`), capture reported `hit_count=3` with `owner_collision=2` while rewrite reported `actual_hits=1`, so effective capture hits matched rewrite hits.
- Using raw `projectile_find_hit_count` for lead/category detection produced false projectile-hit shortfall signatures and misdirected follow-up probes.

### Landed Changes

- `src/crimson/original/divergence_report.py`
  - added `_effective_capture_projectile_hit_count(...)` helper,
  - updated `_find_first_projectile_hit_shortfall(...)` to compare rewrite hit count against effective capture hits (`raw_hits - owner_collision_queries`, clamped at `>= 0`),
  - updated `_classify_divergence_category(...)` to use the same effective-hit metric,
  - updated focus diagnostics printout to show both raw and effective capture projectile-hit counts.
- `tests/test_original_capture_divergence_report_rng_calls.py`
  - added owner-collision guardrail tests for shortfall detection and category classification,
  - updated existing projectile-hit shortfall fixtures to assert both raw and effective hit semantics.

### Validation

- Targeted tests:
  - `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py -q`
- Focus recheck:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache --json-out analysis/frida/reports/session18_unlink_continue_pass6/quest_1_8_after_owner_collision_shortfall_fix_nocache.json` *(expected non-zero exit while diverged)*
    - `result=diverged kind=rng_stream_mismatch tick=7756 focus_tick=7756`
    - `divergence_category.id = rng.tail_shortfall`
    - no `Native projectile hit resolves exceed rewrite hit events` lead in `investigation_leads`
- Full linked-capture no-cache sweep summary:
  - `analysis/frida/reports/session18_unlink_continue_pass6/_summary.tsv` (`21 total`, `0 ok`, `21 diverged`)
- Repository checks:
  - `just check`

### Outcome / Next Probe

- No linked captures are clear in this pass, so there are no new capture unlinks.
- Earliest unresolved frontier remains `quest_1_8 tick 7756`; next probe should continue from movement-drift ancestry and the remaining RNG tail shortfall branch in the `7753-7756` window.

## Session 18 (continued: `quest_1_8` follow-link threshold dead-end probe pack)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz`
- **Capture family:** post-master-rebase quest split set (`session18_alt_leads`)
- **Baseline verifier command (start/end of pass):**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --no-cache`
- **First mismatch progression:**
  - pass start baseline: `tick 7756` (`rng_stream_mismatch`, `rng.tail_shortfall`, missing tail `2`)
  - pass end baseline: unchanged at `tick 7756` (same category/signature)

### Key Findings

- The first decisive branch split in this ancestry is earlier than focus:
  - at `tick 7647`, capture keeps slot `3` on player-force (`force_target(after)=1`), while rewrite flips to link-target (`force_target(after)=0`).
- Extracted raw `creature_update_micro` rows from capture (`event_heads`) and compared against rewrite trajectory at the same window.
- In the edge window (`7638..7650`), rewrite link-distance-before is consistently biased relative to capture:
  - rewrite minus capture bias stays around `+0.126 .. +0.133` through `tick 7647`,
  - crossing behavior at `tick 7647` maps directly to the `< 40.0` force-target threshold branch.
- This indicates cumulative upstream movement ancestry drift; no local constant tweak below isolated the root cause without collateral regressions.

### Dead-End Probes (all reverted)

- `src/crimson/creatures/runtime.py`: `_angle_approach(...)` float-store-boundary variant.
  - result: no `7647` force-target correction; slot drift worsened on control path.
- `src/crimson/creatures/ai.py`: target-heading delta path without pre-rounding dx/dy to `f32`.
  - result: no change in first force-target mismatch tick (`7647` remained).
- `src/crimson/creatures/runtime.py`: turn-rate expression variant (`move_speed * 0.33333334 * 4.0` form).
  - result: no material change in ancestry/frontier.
- `src/crimson/math_parity.py`: `heading_from_delta_f32` using `+1.5707964` literal.
  - result: slight drift changes but no branch/focus improvement.
- `src/crimson/math_parity.py`: disable left-axis tie-break branch.
  - result: no measurable impact in this window.
- `src/crimson/creatures/runtime.py`: movement direction from `heading_to_direction_f32(...)` pre-rounded components.
  - result: no measurable impact in this window.
- `src/crimson/creatures/runtime.py`: movement radians with `-1.5707964` literal.
  - result: severe run-level regression (`run_score_xp=9833`, extra RNG-state-change ticks at `7759/7763/7767`) while still diverged at `7756`.

### Validation

- Baseline no-cache (start): `analysis/frida/reports/session18_continue/quest_1_8_baseline_resume_nocache.json`
- Baseline no-cache (end): `analysis/frida/reports/session18_continue/quest_1_8_baseline_end_of_pass_nocache.json`
- Regression canary (movement half-pi literal probe): `analysis/frida/reports/session18_continue/quest_1_8_after_move_halfpi_constant_probe_nocache.json`
- Edge-window evidence artifact:
  - `analysis/frida/reports/session18_continue/quest_1_8_slot3_force_target_edge_7638_7650.tsv`
- Supplementary trajectory probes generated in this pass:
  - `analysis/frida/reports/session18_continue/_tmp_cre3_7506_7708_angle_store_probe.json`
  - `analysis/frida/reports/session18_continue/_tmp_cre3_7506_7708_target_heading_probe.json`
  - `analysis/frida/reports/session18_continue/_tmp_cre3_7506_7708_turnrate_probe.json`
  - `analysis/frida/reports/session18_continue/_tmp_cre3_7506_7708_halfpi_probe.json`
  - `analysis/frida/reports/session18_continue/_tmp_cre3_7506_7708_no_left_axis_probe.json`
  - `analysis/frida/reports/session18_continue/_tmp_cre3_7506_7708_f32_direction_probe.json`
  - `analysis/frida/reports/session18_continue/_tmp_cre3_7506_7708_move_halfpi_probe.json`

### Outcome / Next Probe

- No gameplay/runtime patch landed from this pass; all probe edits were reverted.
- To avoid repeating dead-end arithmetic tweaks, next run should switch to a different axis:
  - verify replay tick-timing application in the `7638..7650` window (`dt_frame`, `dt_frame_ms_i32`, and `apply_world_dt_steps` behavior) against capture micro `dt_frame` rows,
  - instrument rewrite world-step per-tick/per-slot (`slot 0` and `slot 3`) around pre-AI and post-move boundaries to confirm whether the persistent `~+0.13` link-distance bias is timing-path driven rather than local movement constants.
