---
tags:
  - frida
  - differential-sessions
---

## Session 6 (2026-02-10)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `97268461b6661f4adadafe812a32bd1061a0db94c300f655628dc50688037b7f`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_97268461_after_conflict_context_fix_baseline.json`
- **First mismatch progression:**
  - earlier baseline in this SHA family: `tick 3659 (players[0].experience, score_xp)`
  - after spawn/camera ordering work: `tick 4376 (players[0].pos.x, players[0].pos.y)`
  - after this session’s fixes: `tick 5968 (players[0].experience, score_xp)`

### Key Findings

- Deferred camera update in replay sessions was consuming the first Nuke shake decay step one tick too early:
  - rewrite-only camera RNG at `tick 3630`,
  - missing native camera RNG at `tick 3631`.
- Skipping deferred camera update on Nuke-pickup ticks restored native camera cadence:
  - `tick 3631` aligned (`capture/rewrite 6 calls`),
  - previously-fixed spawn/camera ordering at `ticks 3641/3642` stayed aligned.
- Opposite-direction digital key conflicts are context-dependent in this capture:
  - `tick 224` requires right-turn precedence for `left+right` with no forward/backward,
  - `tick 4376` requires left-turn precedence when forward/backward is active.
- After moving the frontier to `tick 5968`, the new lead is secondary-projectile timing:
  - rewrite emits a large RNG burst at `tick 5958` (181 calls) while native has 1,
  - native shows the matching 181-call burst at `tick 5959` while rewrite has 0,
  - by `tick 5968` rewrite resolves an extra kill (`+84 XP`) with `secondary_projectiles` RNG-heavy activity.

### Landed Changes

- Updated `src/crimson/sim/sessions.py`:
  - defer-camera path now skips `camera_shake_update` on ticks where a Nuke pickup occurs.
- Updated `src/crimson/original/capture.py`:
  - digital conflict resolution now uses contextual precedence:
    - `turn_left+turn_right` with move input -> left,
    - `turn_left+turn_right` without move input -> right,
    - `move_forward+move_backward` with turn input -> forward,
    - `move_forward+move_backward` without turn input -> backward.
- Added/updated regression coverage:
  - `tests/test_camera_shake.py` (deferred-session Nuke camera behavior, survival + rush),
  - `tests/test_original_capture_conversion.py` (contextual conflict precedence).

### Validation

- `uv run pytest tests/test_original_capture_conversion.py tests/test_camera_shake.py tests/test_replay_runners.py tests/test_step_pipeline_parity.py`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 3631 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_focus_3631_after_conflict_context_fix.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 3641 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_focus_3641_after_conflict_context_fix.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 3642 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_focus_3642_after_conflict_context_fix.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 5958 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_focus_5958_after_conflict_context_fix.json`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 5959 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_focus_5959_after_conflict_context_fix.json`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_97268461_after_conflict_context_fix_baseline.json` *(expected non-zero exit while diverged)*
- `just check`

### Outcome / Next Probe

- New actionable frontier: `secondary_projectiles` behavior is one tick early around `5958/5959` and likely causes the `tick 5968` XP mismatch.
- Next probe should target `src/crimson/projectiles.py:update_pulse_gun`, especially the hit-to-detonation transition path (random-heavy decal/sprite/explosion work) to verify whether native defers this burst by one tick.

### Continuation (2026-02-10)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `97268461b6661f4adadafe812a32bd1061a0db94c300f655628dc50688037b7f`

#### Landed Changes

- Updated `src/crimson/sim/world_state.py`:
  - death-SFX preplanning now always calls `plan_death_sfx_keys([death], rand=...)` (RNG parity), while still capping emitted keys to 5.
- Added regression coverage in `tests/test_death_timing.py`:
  - `test_death_sfx_rand_consumes_past_cap` verifies RNG-consuming death-SFX planning continues past the per-frame SFX cap.

#### Validation

- `UV_CACHE_DIR=.uv-cache uv run pytest tests/test_death_timing.py tests/test_projectiles.py`
- `UV_CACHE_DIR=.uv-cache uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 6072 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6072.json`
- `UV_CACHE_DIR=.uv-cache uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 6174 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6174.json`
- `UV_CACHE_DIR=.uv-cache uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 6191 --near-miss-threshold 0.35 --json-out analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6191.json`
- `UV_CACHE_DIR=.uv-cache uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_baseline.json` *(expected non-zero exit while diverged)*
- Additional probes:
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_4527.json`
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_5882.json`
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6076.json`
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6461.json`
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6462.json`
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6469.json`
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6474.json`
  - `analysis/frida/reports/capture_97268461_continue7_death_sfx_rng_cap_fix_focus_6482.json`

#### Outcome

- `tick 6072` RNG shortfall is fixed:
  - `capture_calls=48`, `rewrite_calls=48`, `prefix_match=48`.
- Prior frontier at `6174/6191` is resolved:
  - `6174`: full 185-call secondary burst alignment.
  - `6191`: `capture=1`, `rewrite=1`, full prefix alignment.
- Baseline first mismatch moved to `tick 6462`:
  - `players[0].experience`: expected `7563`, actual `7639`.
  - `score_xp`: expected `7563`, actual `7639`.
- New divergence signature:
  - rewrite triggers secondary hit/detonation burst at `6462` (`secondary_projectiles=183`, +1 death),
  - native triggers the corresponding burst at `6469` (`projectile_find_hit` + `creature_damage` + `creature_death`).

#### Next Probe

- The earliest structural lead is at `tick 4527` (Freeze pickup tick):
  - capture `CreatureSpawnLow` spawns at `pos=(495, 1064)` and lifecycle `added_ids=[12]`, `removed_ids=[24]`,
  - rewrite RNG callsites show freeze-bonus RNG burst first, then `rand_survival_spawn_pos` later in the same tick,
  - capture RNG head shows survival-update callers (`0x00408423`, `0x0040846c`) at the start of the tick.
- Working hypothesis:
  - survival-spawn RNG is consumed too late relative to freeze-bonus RNG in rewrite, producing a different spawned creature trajectory that later causes the `6462` secondary-hit kill timing mismatch.
- Target files for next patch:
  - `src/crimson/sim/sessions.py`
  - `src/crimson/sim/world_state.py`
  - `src/crimson/gameplay.py`

### Continuation (2026-02-10, late)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `97268461b6661f4adadafe812a32bd1061a0db94c300f655628dc50688037b7f`

#### First Mismatch Progression

- after reverting broad projectile deferral and applying owner-collision parity patch: `tick 8135` (`players[0].experience`, `score_xp`)

#### Key Findings

- Native `projectile_update` (`0x00420e52`) uses `creature_find_in_radius(..., 0)` and treats `owner_id` returns as non-hits for damage, rather than continuing to later creature candidates in that step.
- At `tick 7683`, matching this owner-collision branch behavior removed rewrite-only hit/RNG activity and advanced the frontier.
- At `tick 8128`, native resolves additional `projectile_find_hit` rows (including corpse-hit repeats) that the rewrite still misses; this creates RNG tail shortfall and later XP divergence at `8135`.
- Existing telemetry showed only successful `projectile_find_hit` results, which was insufficient to distinguish miss-vs-owner-collision query paths at branch points.

#### Landed Changes

- Updated `src/crimson/projectiles.py`:
  - owner-collision handling now mirrors native `projectile_update` branch behavior for creature-hit resolution.
  - tracked shock-chain slot now mirrors native `player_find_in_radius` skip behavior in that branch.
- Updated capture telemetry in `scripts/frida/gameplay_diff_capture.js`:
  - new `projectile_find_query` event stream for all projectile-update `creature_find_in_radius` calls (hits + misses),
  - includes query result kind, projectile slot/type/owner context, owner-collision marker, and shock-chain skip marker,
  - adds top-caller + miss/owner-collision diagnostics to per-tick spawn debug.
- Updated consumers:
  - `src/crimson/original/schema.py` adds `projectile_find_query` event-head + count support,
  - `src/crimson/original/divergence_report.py` ingests/prints new query diagnostics and investigation evidence,
  - coverage in `tests/test_original_capture_conversion.py` and `tests/test_original_capture_divergence_report_rng_calls.py`.
- Verification cleanup/fidelity:
  - `src/crimson/original/verify.py` now accepts the known single-tick world-step creature-count latch case.

#### Validation

- `just check`

#### Outcome / Next Probe

- Current frontier remains `tick 8135` on this SHA.
- Next session should use a fresh capture with the new `projectile_find_query` telemetry enabled to isolate whether the remaining `8128+` shortfall is miss-path or owner-collision-path driven before further gameplay rewrites.

### Tooling Reset (2026-02-11)

- Capture format tightened to stream rows only (`capture_meta` + `tick`); legacy monolithic JSON capture files are no longer supported by loader tooling.
- Float capture contract tightened: memory-sourced float samples are emitted as tagged float32 bit tokens (`f32:XXXXXXXX`) and decoded in Python loader as authoritative float32 values.
- Removed temporary verify fallback that ignored one-tick `creature_count` lag; verification now depends on aligned capture sampling and sample-stream parity instead of lag allowances.

---

