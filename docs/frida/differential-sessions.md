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
