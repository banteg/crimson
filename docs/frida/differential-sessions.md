# Differential Capture Sessions (Condensed)

This log tracks original-vs-rewrite differential work by **capture SHA**.
When the capture SHA is unchanged, append updates to the same session.

## Session Template

- **Title:** `Session <N> (YYYY-MM-DD)`
- **Legacy IDs:** `<optional old IDs>`
- **Capture:** `<path>`
- **Capture SHA256:** `<sha256 or n/a>`
- **Baseline verifier command:** `<exact command>`
- **First mismatch:** `tick <n> (<fields>)`

### Key Findings

- `<highest-signal findings only>`

### Landed Changes

- `<important code/tooling/doc changes only>`

### Outcome / Next Probe

- `<what remains, and where to probe next>`

---

## Capture Policy (Current)

- Default to full-detail `gameplay_diff_capture` captures (no focus window, no sample limits).
- Keep `artifacts/frida/share/gameplay_diff_capture.json` as the canonical artifact and always log SHA256.
- Use `--run-summary` or `--run-summary-short` in divergence reports.
- If any env knobs throttle capture volume, log exact knob/value.
- If capture SHA is unchanged, update the existing session; do not create a new one.

---

## Session 1 (2026-02-08)

- **Legacy IDs:** `2026-02-08-a` .. `2026-02-08-e`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 20 --json-out`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Key Findings

- Rewrite awarded a rewrite-only kill at tick `1794` (`+41 XP`), tied to secondary projectile behavior.
- Pre-divergence RNG drift existed in AI7 timer paths, but disabling that behavior caused earlier regressions (not root fix).
- Capture coverage was initially insufficient for direct geometry/hit-resolution comparison at divergence ticks.

### Landed Changes

- Added divergence tooling upgrades:
  - `--run-summary` and later `--run-summary-short` outputs.
  - rewrite RNG-call inference and stage-attribution diagnostics.
  - sample-coverage/blocker reporting in divergence output.
- Added capture telemetry:
  - secondary projectile spawn hooks and secondary sample capture.
- Landed gameplay parity patch in `src/crimson/projectiles.py` for native-like secondary homing target semantics (active + hitbox sentinel behavior).

### Outcome / Next Probe

- Session closed when a new recording moved divergence to a later and different profile (`tick 3504` on next SHA), indicating this capture family had been exhausted.

---

## Session 2 (2026-02-08)

- **Legacy IDs:** `2026-02-08-f` .. `2026-02-08-o`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out`
- **First mismatch:** `tick 3504 (players[0].experience, score_xp)`

### Key Findings

- Primary signal moved earlier than the XP mismatch:
  - first major pre-focus RNG shortfall at `tick 3453` (`expected 353`, rewrite `268`, missing `85`).
- RNG values matched perfectly for rewrite’s prefix (`prefix_match=268`), with a native-only tail.
  - This indicates a missing branch sequence, not wrong RNG values in shared branches.
- Caller-gap diagnostics isolated one missing hit-equivalent presentation loop at `tick 3453` (Fire-Bullets/Gauss path).
- Narrow float32/trig movement experiments changed geometry margins but did **not** move first mismatch (`3504`) or shortfall tick (`3453`).

### Landed Changes

- Added major investigation tooling:
  - `original focus-trace` (callsite RNG, collision near-miss, indexed sample diffs).
  - RNG value-alignment and native-only tail diagnostics.
  - caller-gap and loop-parity summaries.
  - `original creature-trajectory` enhancements for long-horizon slot drift.
- Added telemetry for projectile-hit resolution (`projectile_find_hit`, corpse-hit markers).
- Added shared parity helpers and precision-boundary cleanup groundwork:
  - `src/crimson/math_parity.py`
  - targeted updates in `src/crimson/creatures/ai.py` and `src/crimson/creatures/runtime.py`
  - corresponding tests.

### Outcome / Next Probe

- Unresolved at end of SHA family: missing hit-resolution branch(es) around `projectile_update` remained.
- Next required probe: branch-order parity in projectile hit/corpse-hit handling, not broader float cleanup.

---

## Session 3 (2026-02-09)

- **Legacy IDs:** `2026-02-09-p`
- **Capture:** `n/a (tooling-only session)`
- **Capture SHA256:** `n/a`
- **First mismatch:** `n/a`

### Key Findings

- Absolute ticks are weak cross-session anchors once chronology diverges.
- RNG-order anchors (`seq`, per-tick call index, seed epoch) are required for reliable cross-run alignment.

### Landed Changes

- Upgraded `scripts/frida/gameplay_diff_capture.js` RNG diagnostics:
  - per-roll sequence metadata, between-tick carry, optional full roll log, CRT mirror integrity counters.
- Extended `original divergence-report` to surface sequence/epoch anchors and mirror totals.
- Updated `docs/frida/gameplay-diff-capture.md` with full RNG trace profile guidance.

### Outcome / Next Probe

- Prepared instrumentation for the next capture family; no gameplay parity fix in this session.

---

## Session 4 (2026-02-09)

- **Legacy IDs:** `2026-02-09-q`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `28b8db6eb6b679455dad7376ef76149d26fdd7339dea246518685938cdb48662`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 40 --json-out`
- **First mismatch progression:**
  - initial: `tick 1069 (players[0].ammo)`
  - after replay/input + movement fixes: `tick 3882 (players[0].experience, score_xp)`
  - after capture-RNG map + timer/reload parity fixes: `tick 4421 (players[0].ammo, players[0].weapon_id)`
  - after hit/collision + AI float32 parity fixes: `tick 7466 (players[0].experience, score_xp)`

### Key Findings

- Early divergence (`tick 1069`) was driven by replay input reconstruction mismatch (rewrite firing where native did not).
- `tick 3624` “missing perk RNG” was a tooling false-positive: those draws happened in replay events, outside world-step RNG marks.
- Per-tick `rng.outside_before_calls` replay must special-case tick 0 (bootstrap draws already baked into inferred seed).
- Native `bonus_update` clamps `double_xp/freeze` to `0.0` when timer `<= 0.0`; missing this caused `-8ms` carry and `tick 4311` timer drift.
- Reload timing is float-boundary sensitive: using float32-style reload math plus native preload ordering moved ammo parity to native at `tick 4396`.
- Strict float32 sequencing in creature AI distance/orbit paths fixed a corpse-hit timing miss at `tick 6958` and moved the frontier to `tick 7466`.
- The current `tick 7466` XP divergence is downstream of RNG stream drift:
  - first clear native-only RNG tail is at `tick 7336` (`perk_select_random` shortfall `2` draws),
  - by `tick 7440` RNG values are already offset at the first draw in `player_fire_weapon`,
  - rewrite then resolves a kill at `tick 7466` that native does not.
- Local diagnostic replay with `+2` synthetic draws before `tick 7337` moves first mismatch to `tick 8593`, confirming the `7336` missing-tail branch as the dominant blocker.
- Existing capture lacks explicit perk-apply IDs, so we cannot faithfully replay native perk selections for this SHA family.

### Landed Changes

- `fix(gameplay): mirror float32 movement store boundaries` (`da0a12de`)
- `fix(replay): align capture input and perk reconstruction` (`d9f6815e`)
  - improved fire fallback semantics
  - frame-dt precision preference
  - inferred perk menu/pending event reconstruction
- `fix(creatures): round ai7 timer dt_ms to native boundary` (`bb88cfa8`)
- Added event-phase RNG checkpoint marks and event-aware divergence accounting in replay runners/reporting.
- Extended focus-trace RNG interception to cached pool RNG hooks (`particles._rand`, `sprite_effects._rand`).
- Added parser support for `rng.outside_before_calls` and wired per-tick outside-draw replay.
- Patched `bonus_update` timer clamp semantics for `double_experience` and `freeze`.
- Patched reload timing semantics in `player_update` (native preload ordering + float32-style reload timer arithmetic + anxious-loader tail behavior).
- Added strict float32 AI distance/orbit intermediates in `src/crimson/creatures/ai.py`.
- Added perk-apply capture telemetry (`perk_apply`, `perk_apply_outside_before`) and replay-side event support (`orig_capture_perk_apply_v1`) so future captures can replay explicit perk picks.
- `docs(frida): renumber sessions and fold same-sha updates` (`90f5637e`)

### Validation

- `uv run pytest tests/test_player_update.py tests/test_original_capture_conversion.py tests/test_replay_perk_menu_open_event.py tests/test_creature_runtime.py`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 3624 --near-miss-threshold 0.35 --json-out`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.json --tick 7336 --near-miss-threshold 0.35 --json-out`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 40 --json-out` *(expected non-zero exit while diverged)*

### Outcome / Next Probe

- Blocked on missing perk-selection identity in this capture: the replay can observe pending/menu transitions but cannot know which perk native applied at each menu close.
- Record a new capture with the updated script (perk-apply telemetry enabled by default), then verify that replayed `orig_capture_perk_apply_v1` events remove the `tick 7336` RNG tail and push the first mismatch beyond `tick 7466` using event/RNG anchors (not absolute-tick equality).
- Next session cleanup: once a fresh capture confirms stable key-state telemetry, remove temporary replay fallbacks in `src/crimson/original/capture.py` that synthesize/mix input from partial fields.

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

## Session 7 (2026-02-11)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `16f67e1397e4ec0ee7209aec07a5f1eb604c574a52249df1ebf74826dd1441d1`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_16f67e_abandon_baseline.json`
- **First mismatch:** `tick 29 (players[0].pos.x, players[0].pos.y)`

### Key Findings

- Earliest drift is pre-combat movement (`tick 29`) with no RNG mismatch (`rand_calls delta = 0`), indicating input reconstruction/capture mismatch rather than simulation-side combat logic.
- Capture telemetry at `tick 29` shows `turn_left_pressed=true` and no forward key in `input_player_keys`, while `input_approx.move_dy=-2.227553367614746` indicates forward-like motion was applied by native.
- Ghidra `player_update` shows single-player alternate bindings use `grim_is_key_down` fallback checks when primary binding is not active:
  - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:12337`, `analysis/ghidra/raw/crimsonland.exe_decompiled.c:12355`, `analysis/ghidra/raw/crimsonland.exe_decompiled.c:12378`, `analysis/ghidra/raw/crimsonland.exe_decompiled.c:12387`.
- Grim vtable mapping confirms slot `0x44` is `grim_is_key_down` (`analysis/ghidra/derived/grim2d_vtable_map.csv:19`), and Grim decompile confirms this path reads keyboard down-state (`analysis/ghidra/raw/grim.dll_decompiled.c:3876`).

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
  - snapshot `config_aim_scheme` is absent,
  - `input_player_keys.fire_down/fire_pressed` is often `null`/`false`,
  - `fired_events` is always `0`.
- The run is known to use sidecar-configured `config_aim_scheme=5` (Computer), but that value is not encoded in this artifact.
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
  - `scripts/frida/gameplay_diff_capture.js` now emits per-player `config_player_mode_flags` and `config_aim_scheme` in globals and `input_approx`.
- Added mode-5 parity in controls UI:
  - `src/crimson/frontend/panels/controls_labels.py`
  - `src/crimson/frontend/panels/controls.py`
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

## Session 10 (2026-02-12)

- **Capture:** `/Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `8d6cb578c32252b536971a12891e7701b22e3d2b3117015bca1f38567849aa41`
- **First mismatch:** `n/a (tooling/performance session)`

### Key Findings

- Baseline uncached timings on this capture:
  - `uv run crimson original divergence-report <capture> --no-cache`: `56.34s`.
  - `uv run crimson original divergence-report <capture> --no-cache --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30`: `75.24s`.
  - `uv run crimson original focus-trace <capture> --tick 389 --no-cache`: `19.73s`.
  - `uv run crimson original focus-trace <capture> --tick 10000 --no-cache`: `69.75s`.
- Cached daemon timings after clearing sidecars and restarting cold:
  - cold: `divergence-report` triage command `44.51s`.
  - hot: same `divergence-report` triage command `0.20s`.
  - `focus-trace --tick 389`: `0.71s`.
  - nearby `focus-trace --tick 390`: `0.17s`.
  - backward-nearby `focus-trace --tick 388`: `0.19s`.
  - far `focus-trace --tick 10000`: `52.47s`.
  - adjacent after far `focus-trace --tick 10001`: `0.17s`.

### Landed Changes

- Added hybrid cache daemon + sidecar caching for `original divergence-report` and `original focus-trace`.
- Added `--no-cache` opt-out and environment knobs:
  - `CRIMSON_ORIGINAL_CACHE=0|1`
  - `CRIMSON_ORIGINAL_CACHE_DIR`
  - `CRIMSON_ORIGINAL_CACHE_SOCKET`
- Added daemon fallback behavior to preserve local in-process execution when cache mode is unavailable.

### Validation

- `uv run pytest tests/test_original_diagnostics_cache.py tests/test_original_diagnostics_daemon.py`
- `uv run ruff check src/crimson/original/diagnostics_cache.py src/crimson/original/diagnostics_daemon.py src/crimson/original/divergence_report.py src/crimson/original/focus_trace.py src/crimson/cli.py tests/test_original_diagnostics_cache.py tests/test_original_diagnostics_daemon.py`
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --no-cache`
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --no-cache --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 389 --no-cache`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 10000 --no-cache`
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30` (cold + hot)
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 389`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 390`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 388`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 10000`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 10001`

### Outcome / Next Probe

- Hot-path targets are met for repeated same-capture diagnostics (`<=2s divergence hot`, `<=1s nearby focus hot`).
- Remaining cold-path bottleneck is far-tick focus replay stepping; next optimization should prioritize stronger anchor coverage or compact state snapshot restore for long-range random tick access.

---

## Session 11 (2026-02-12)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `421afa2fc10f307d784d492d2ccbda914deb50400348904a156dc9a5dab7eb0a`
- **First mismatch progression:**
  - transient: `tick 495 (players[0].ammo)` self-heals at `tick 496`
  - sustained: `tick 671 (rng_stream_mismatch)`

### Key Findings

- `tick 671` is a **Weapon** pickup, not Freeze:
  - `bonus_apply` head is `bonus_id=3`,
  - same tick has `weapon_assign` (`weapon_before=1`, `weapon_after=14`),
  - `bonus_timers["11"]` (Freeze) is `0`.
- Capture head truncation is not the issue in this run:
  - `event_overflow=false` across the capture.
- Fire telemetry quality is insufficient for confident replay input synthesis:
  - `event_counts.player_fire` is `0` on all `11,145` ticks,
  - player-owned `projectile_spawn` appears on `1,012` ticks.
- Root instrumentation issue: `scripts/frida/gameplay_diff_capture.js` only hooked Typ-o fire entry (`0x00444980`) for `player_fire`, while classic modes fire from `player_update` paths (projectile caller statics under `0x004136b0..0x00417640`).
- Input key aggregation also dropped fire evidence inside a tick:
  - `input_player_keys.fire_down/fire_pressed` was overwritten by later false queries,
  - mouse-primary queries were not mapped into `input_player_keys.fire_*`.

### Landed Changes

- Updated `scripts/frida/gameplay_diff_capture.js`:
  - documented `0x00444980` as Typ-o-only fire entrypoint,
  - added `ownerIdToPlayerIndex` helper and `player_fire` fallback synthesis from player-owned `projectile_spawn` calls within `player_update` caller range,
  - added per-tick fire diagnostics:
    - `player_fire.top_direct_events_by_player`
    - `player_fire.top_fallback_events_by_player`
    - `player_fire.top_player_projectile_spawns_by_player`
  - changed `input_player_keys` fire/reload tracking to **sticky true** within a tick (once true, stays true for that tick),
  - mapped mouse primary queries (`grim_is_mouse_button_down`, `grim_was_mouse_button_pressed`) to player 0 `fire_down`/`fire_pressed`.
- Updated replay conversion to handle same-tick weapon swaps in computer-aim synthesis:
  - `src/crimson/original/capture.py` now checks both current and previous checkpoint weapon id hints when inferring `fire_down` from player-owned projectile spawns.
  - Added regression coverage in `tests/test_original_capture_conversion.py` for weapon-bonus swap ticks (`1 -> 14`) where the spawned projectile type still matches the pre-swap weapon.
- Updated reload boundary parity in `src/crimson/gameplay.py`:
  - added underflow epsilon guard to avoid premature preload on tiny float32 underflow,
  - kept `reload_active` latched until ammo is actually available,
  - mirrored native "top up on next fire tick after reload completion" behavior for empty clips.
  - Added regressions in `tests/test_player_update.py`.

### Validation

- `node --check scripts/frida/gameplay_diff_capture.js`
- `uv run python - <<'PY'`
  ```python
  from pathlib import Path
  from crimson.original.capture import load_capture

  cap = load_capture(Path("artifacts/frida/share/gameplay_diff_capture.json.gz"))
  player_fire_total_count = 0
  ticks_with_player_projectile_spawn = 0
  ticks_with_player_projectile_spawn_but_player_fire_count0 = 0
  overflow = False
  for t in cap.ticks:
      if bool(t.event_overflow):
          overflow = True
      has_player_projectile_spawn = False
      for h in t.event_heads:
          d = h.data
          if "requested_type_id" in d and int(d.get("owner_id", -9999)) == -100:
              has_player_projectile_spawn = True
      player_fire_total_count += int(t.event_counts.player_fire)
      if has_player_projectile_spawn:
          ticks_with_player_projectile_spawn += 1
          if int(t.event_counts.player_fire) <= 0:
              ticks_with_player_projectile_spawn_but_player_fire_count0 += 1
  print(player_fire_total_count, ticks_with_player_projectile_spawn, ticks_with_player_projectile_spawn_but_player_fire_count0, overflow)
  PY
  ```
  output: `0 1012 1012 False`

### Outcome / Next Probe

- This SHA should be treated as tooling-limited for further parity fixes.
- Next step is to record a fresh capture with the patched script, then re-run:
  - `uv run crimson original divergence-report ... --run-summary-focus-context`
  - `uv run crimson original focus-trace ... --tick <first sustained mismatch>`
  - telemetry quality check (`player_fire` vs player-owned `projectile_spawn`) before gameplay patches.

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
  - `config_aim_scheme` and `input_approx.aim_scheme` both present for all ticks.
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

## Session 13 (2026-02-12)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `25ef6718185ed9615d1a172caec2870689148723bb27ab113caee0b170b22599`
- **First mismatch progression:**
  - sustained (`divergence-report`): `tick 6514 (rng_stream_mismatch, missing_tail=87)`
  - checkpoint-state verifier (`verify-capture`): `tick 6527 (players[0].experience +53)`

### Key Findings

- Baseline on current rewrite branch remains late-run divergent:
  - `divergence-report` focuses at `tick 6514` with `rand_calls(e/a)=722/635` and `capture_projectile_find_hit_count=8` vs `rewrite_hits=7`.
  - `verify-capture` first fails at `tick 6527` (`score_xp`/`players[0].experience` expected `42127`, actual `42180`).
- Existing capture telemetry is insufficient for the remaining root-cause around `tick 6514`:
  - `sample_creature_rows=313581`,
  - `sample_creature_rows_with_ai_lineage=0`,
  - `creature_lifecycle_rows=1613`,
  - `creature_lifecycle_rows_with_ai_lineage=0`.
- Spot checks at `tick 6514` confirm creature snapshots under `samples.creatures`, `projectile_find_hit.creature`, and `creature_damage`/`creature_death` payloads have no `ai_mode`/`link_index` lineage data, so AI7 timer/link transitions cannot be distinguished from replay/runtime drift.

### Landed Changes

- Added AI-lineage telemetry to capture instrumentation:
  - `scripts/frida/gameplay_diff_capture.js` now records `link_index`, `ai_mode`, `heading`, `target_heading`, `orbit_angle`, `orbit_radius`, and `ai7_timer_ms` in creature sample/lifecycle snapshots used by event heads and lifecycle deltas.
- Extended typed loader schema for creature samples:
  - `src/crimson/original/schema.py` (`CaptureCreatureSample`) now accepts optional AI-lineage fields.
- Surfaced lineage fields in diagnostics summaries:
  - `src/crimson/original/divergence_report.py` and `src/crimson/original/diagnostics_cache.py` now include AI-lineage fields in `sample_creatures_head` when present.
- Updated capture docs/playbook:
  - `docs/frida/gameplay-diff-capture.md` documents creature lineage telemetry.
  - `docs/frida/differential-playbook.md` telemetry quality snippet now reports lineage coverage for `samples.creatures` and `creature_lifecycle` rows.
- Added regression coverage:
  - `tests/test_original_capture_conversion.py` validates typed sample parsing with AI-lineage fields.
- Commit: `9ba15b93` (`fix(frida): capture creature ai lineage telemetry`).

### Validation

- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_25ef6718_post_pr_baseline.json` *(expected non-zero exit while diverged)*
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32` *(expected non-zero exit while diverged)*
- `uv run python - <<'PY' ...` telemetry quality check (key/perk + AI-lineage coverage) against `artifacts/frida/share/gameplay_diff_capture.json.gz`.
- `uv run pytest tests/test_original_capture_conversion.py -k 'strict_typed_sample_rows or player_fire_debug_payloads'`
- `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_diagnostics_cache.py`
- `just check`

### Outcome / Next Probe

- This capture SHA is now **abandoned for further parity root-cause work** near `tick 6514`: the required AI lineage telemetry was not present in the already-recorded artifact and cannot be reconstructed post hoc.
- Next session should start with a fresh `gameplay_diff_capture` recording using the patched script, then immediately gate on telemetry quality:
  - `sample_creature_rows_with_ai_lineage > 0`,
  - `creature_lifecycle_rows_with_ai_lineage > 0`.
- After a fresh capture passes that gate, repeat:
  - `divergence-report --run-summary-focus-context`,
  - `verify-capture`,
  - `focus-trace --tick <first sustained mismatch>`.

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

---

## Session 15 (2026-02-13)

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
  - `analysis/ghidra/raw/crimsonland.exe_decompiled.c` (`player_update` around `0x004136b0`, `frame_dt` temporary rescale/restore),
  - `src/crimson/gameplay.py`,
  - `src/crimson/sim/world_state.py`.

---

## Session 16 (2026-02-13)

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

---

## Session 17 (2026-02-13)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `49aec5d3705f7c8cfb90143a6d204053c8ba6744ca30c4a367666cdaec04fe0e`
- **First mismatch progression:**
  - baseline after Session 16 fix (`0974bf4d`): `tick 9065 (state_mismatch: players[0].experience/score_xp +110 in replay)`
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
- `sg run -p 'while ($COND) { $$$BODY }' analysis/ghidra/raw/crimsonland.exe_decompiled.c -l c --json=stream` (structural scan over decompile loops including `angle_approach`/movement loop forms)

### Outcome / Next Probe

- **Hard block with current capture granularity:** first visible slot-31 drift is sub-ULP-scale and accumulative (`8736+`), but current telemetry lacks per-creature pre/post movement internals to isolate which native arithmetic/branch diverges first.
- Next required capture probe should add creature-update micro-telemetry for targeted slots/ticks:
  - per-creature pre/post `heading`, `target_heading`, `force_target`, `ai_mode`, `move_scale`,
  - per-creature `angle_approach` inputs/step outputs (`angle`, `target`, `rate`, chosen branch),
  - raw `target_x/target_y` and `dist_to_target` comparisons used by `<40` / `>400` forcing,
  - emitted at least for slot `31` around `8679..9014` and the player-chase onset window (`8730..8900`).
