---
tags:
  - frida
  - differential-sessions
---

## Session 17 (2026-02-18)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_*.json`
- **Capture Family:** split quest captures from `session_id=0xc75a5b93`
- **Capture SHA256:** per-file SHA set (32 files, all valid); representative focus file:
  - `gameplay_diff_capture.quest_1_7.json`: `2d7c0c864cd378dd34194f2a2ed2de41e8478808f9c75a3a38395bbab1b002e4`
- **Baseline verifier command (sweep):**
  `for f in artifacts/frida/share/gameplay_diff_capture.quest_*.json; do uv run crimson original divergence-report "$f" --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 10 --no-cache --json-out "analysis/frida/reports/session20_sweep_current/${f##*/}_baseline_nocache.json"; done`
- **First mismatch progression:**
  - early baseline in this family: `quest_1_6 tick 6177 (rng_stream_mismatch)`, `quest_1_7 tick 7880 (rng_stream_mismatch)`
  - after landed fixes in this session: `quest_1_6 clean`, earliest unresolved moved to `quest_1_7 tick 8529 (rng_stream_mismatch)`
  - current full sweep: `9/32` captures clean; earliest unresolved remains `quest_1_7 tick 8529`

### Key Findings

- Capture quality gate passed for all 32 quest files:
  - JSON parse/load succeeds for every file,
  - `creature_update_micro_rows > 0`, `angle_approach > 0`, and `creature_update_window > 0` in all files.
- Remaining frontier is stable at `quest_1_7`:
  - pre-divergence tail at `tick 8528`: `rand_calls capture/rewrite = 157/166` with stream prefix match for the captured head,
  - first stream value mismatch at `tick 8529` (`idx=0`, capture branch id `0x004263b1`).
- Divergence-report evidence points to projectile presentation/decal branch skew near the `8528 -> 8529` handoff, with downstream XP/perk drift in later quest splits.
- `original focus-trace` currently rejects quest-mode captures (`mode=3`), so we cannot obtain rewrite-side per-callsite attribution at the frontier from existing tooling.

### Landed Changes

- Replay/capture conversion parity:
  - added quest capture event replay for creature spawns and state transitions,
  - expanded bootstrap payload/apply to include richer pre-tick player/runtime fields, perk nonzero counts, perk intervals, and quest session timers,
  - added fire/reload synthesis fixes for alt-weapon swap, fractional-ammo weapons, and zero-cooldown `player_fire` proc rows.
- Quest replay runtime parity:
  - original-capture quest replays now consume capture spawn hooks as authoritative,
  - added capture-driven state-transition reset path,
  - aligned original-capture dt-step application behavior in quest session wiring.
- Gameplay/perk parity:
  - preserved same-tick fire gate across alt-weapon swap,
  - hot-tempered perk projectiles now spawn from pre-move player position.
- Creature/runtime parity:
  - owner spawn-slot tick moved into creature loop tail with random heading sentinel for child spawn plan parity,
  - added native-like ping-pong corpse blood burst RNG budget path,
  - threaded `gore_disabled` through creature update/decal spawn paths.
- Perk selection parity:
  - quest `1-7` Monster Vision forced insert now respects capture certainty of player perk counts.

### Validation

- `just check`
- Full quest sweep summary written to:
  - `analysis/frida/reports/session20_sweep_current/_summary.tsv`
- Focused unresolved frontier probe:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_7.json --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 6 --run-summary-short-max-rows 40 --no-cache --json-out analysis/frida/reports/session20_sweep_current/gameplay_diff_capture.quest_1_7_focusctx_nocache.json` *(expected non-zero exit while diverged)*

### Outcome / Next Probe

- **Current wall for this capture family:** earliest unresolved divergence (`quest_1_7 tick 8529`) needs rewrite-side per-callsite RNG attribution in quest mode; current tooling cannot provide that because `focus-trace` is survival-only.
- Next probe should be tooling-first before more gameplay patches:
  - add quest-mode support to `original focus-trace`, or
  - add rewrite-side RNG callsite/branch-id trace capture for quest ticks around `8528..8530`.

### Session 17 (continued: tooling update)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.quest_1_7.json`
- **Baseline verifier command:**
  `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.quest_1_7.json --tick 8528 --near-miss-threshold 0.35 --top-rng 5 --near-miss-limit 3 --diff-limit 3 --no-cache`
- **Tooling status change:**
  - before: `focus-trace` rejected quest captures (`mode=3`),
  - after: quest mode is supported in both no-cache and cached focus-trace paths.

### Key Findings

- The blockage noted above was tooling-only and reproducible in both runtime paths:
  - direct `focus-trace --no-cache`,
  - cached diagnostics runtime (`CaptureSession.get_focus_report`).
- Quest-mode focus tracing requires parity with replay-runner quest bootstrap semantics:
  - quest spawn-table/session bootstrap,
  - capture bootstrap timer offsets,
  - capture state-transition reset callback,
  - authoritative capture creature spawn hooks for original-capture quest replays.

### Landed Changes

- `src/crimson/original/focus_trace.py`
  - extended `trace_focus_tick` to support quest mode (`GameMode.QUESTS`) end-to-end.
  - added richer replay-event metadata (`bootstrap_start_tick`, quest spawn-event presence).
  - mirrored quest bootstrap/session-reset logic from quest replay runner.
- `src/crimson/original/diagnostics_cache.py`
  - generalized `_FocusRuntime` to support both survival and quest modes.
  - added quest bootstrap timer handling, capture state reset flow, and quest session stepping.
  - fixed anchor restore to preserve pending quest state-reset flag.
- Tests:
  - `tests/test_original_capture_focus_trace.py`
  - `tests/test_original_diagnostics_cache.py`
  - added quest-mode coverage for focus tooling entry/runtime paths.

### Validation

- `just check`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.quest_1_7.json --tick 8528 --near-miss-threshold 0.35 --top-rng 5 --near-miss-limit 3 --diff-limit 3 --no-cache`
- `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.quest_1_7.json --tick 8528 --near-miss-threshold 0.35 --top-rng 5 --near-miss-limit 3 --diff-limit 3`

### Outcome / Next Probe

- The quest tooling wall is removed; `focus-trace` now produces actionable quest tick reports at the frontier.
- Next probe remains the unresolved gameplay divergence at `quest_1_7 tick 8529`, now using quest-mode focus traces for per-callsite attribution around `8528..8530`.

### Session 17 (continued: quest split follow-up)

- **Capture family:** `artifacts/frida/share/gameplay_diff_capture.quest_*.json`
- **Branch:** `feat/diff-quests`
- **First mismatch progression:**
  - before this follow-up: `quest_1_8 tick 9760 (rng_stream_mismatch)` after `quest_1_7` was cleared,
  - after landed fixes in this update: earliest unresolved remains `quest_1_8 tick 9760`,
  - full no-cache sweep after commits: `10/32` captures clean.

### Key Findings

- `quest_1_8` remains stable at `tick 9760` with:
  - missing projectile hit resolve (`capture_hits=2`, `rewrite_hits=1`),
  - capture RNG tail shortfall (`capture_calls=198`, `rewrite_calls=100`, missing `98` calls),
  - dominant missing native RNG callers from blood/ion-hit FX (`fx_queue_add_random`, `effect_spawn_blood_splatter`, `effect_spawn_ion_hit_sparks`).
- Sequential `_FocusRuntime` sweep localized pre-focus drift:
  - slot `0` (`ai_mode=0`, `link_index=-802`) accumulates tiny heading/position deltas from early in the run,
  - first large branch split appears at `tick 9694` when near-`2pi` heading normalization flips to a different turn branch,
  - this yields the missing second hit at `tick 9760`.
- `angle_approach` implementation is not the direct culprit:
  - replay helper output matches captured `creature_update_micro.angle_approach` rows when fed captured inputs,
  - drift therefore starts upstream (state/input precision accumulation before the callsite branch flip).

### Landed Changes

- `fix(tooling): align quest diagnostics with dt and lifecycle timing` (`01fce35e`)
  - threaded quest `dt_frame_ms_i32` overrides through replay runner and focus runtimes,
  - aligned no-cache/cached focus runtimes with replay header `detail_preset`/`gore_disabled`,
  - unified inter-tick RNG draw overrides via capture helper,
  - deferred quest creature `finalize_post_render_lifecycle` to runner/focus post-event phase for parity.
- `fix(replay): carry quest added_head lifecycle overrides` (`22113f6e`)
  - capture conversion now emits quest spawn replay events when lifecycle `added_head` rows exist even without `creature_spawn` rows,
  - replay event application now applies `added_head` overrides (`heading`, `target_heading`, `ai_mode`, `link_index`) to active indexed entries,
  - added conversion/runtime regression tests for both spawn+added and added-only payloads.

### Validation

- Targeted tests:
  - `uv run pytest tests/test_original_capture_conversion.py::test_convert_capture_to_replay_emits_quest_creature_spawn_events tests/test_original_capture_conversion.py::test_convert_capture_to_replay_emits_quest_added_head_without_spawn_rows tests/test_replay_runners.py::test_capture_creature_spawn_event_applies_added_head_overrides tests/test_replay_runners.py::test_capture_creature_spawn_event_applies_added_head_without_spawn_rows`
  - `uv run pytest tests/test_replay_runners.py::test_quest_runner_disables_world_dt_steps_for_original_capture_dt_overrides tests/test_replay_runners.py::test_quest_runner_uses_capture_creature_spawn_events_for_original_capture_replay`
- Focused frontier recheck:
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 6 --run-summary-short-max-rows 40 --no-cache --json-out analysis/frida/reports/session20_sweep_current/gameplay_diff_capture.quest_1_8_after_added_head_lifecycle_fix_nocache.json` *(expected non-zero exit while diverged)*
- Full post-commit sweep:
  - `for f in artifacts/frida/share/gameplay_diff_capture.quest_*.json; do uv run crimson original divergence-report "$f" --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 10 --no-cache --json-out "analysis/frida/reports/session20_sweep_after_commits/${f##*/}_baseline_nocache_after_commits.json"; done`
  - summary: `analysis/frida/reports/session20_sweep_after_commits/_summary.tsv`

### Outcome / Next Probe

- **Current wall with this capture data:** earliest unresolved frontier (`quest_1_8 tick 9760`) is driven by sub-ULP cumulative movement/heading drift that flips a branch before focus; existing telemetry is head-capped and insufficient to isolate the first causative arithmetic branch for all relevant slots.
- Required next capture probe:
  - increase `creature_update_micro` head budget (or targeted-slot capture) around `tick 9400..9760`,
  - include deterministic per-slot pre/post movement internals for all candidate slots in the drift ancestry window.

### Session 17 (continued: full added-head replay fields)

- **Capture family:** `artifacts/frida/share/gameplay_diff_capture.quest_*.json`
- **Branch:** `feat/diff-quests`
- **First mismatch progression:**
  - before this update: `quest_1_8 tick 9760 (rng_stream_mismatch)`,
  - after this update: earliest unresolved remains `quest_1_8 tick 9760`.

### Key Findings

- Replay previously carried only a subset of lifecycle `added_head` fields (`heading/target_heading/ai_mode/link_index`).
- Extending conversion+replay application to include full `added_head` row state (`pos/hp/lifecycle_stage/orbit/flags/type_id`) is structurally required for parity across capture families, even though it does not move this specific frontier.
- `quest_1_8` remains stable at `tick 9760` after the full-field patch.
- Focused quest probes show the same dominant profile:
  - slot `0` branch split near `tick 9694`,
  - missing second projectile hit and missing RNG tail (`-98`) at `tick 9760`.
- Additional player-movement precision probes identified a one-ULP player `pos.y` drift beginning at `tick 9402`, but source-level movement-rounding experiments did not move the first divergence tick and were not kept.

### Landed Changes

- `src/crimson/original/capture.py`
  - added `capture_creature_spawn_added_head_rows_from_event_payload(...)` to preserve full row objects,
  - retained tuple parser compatibility via `capture_creature_spawn_added_head_from_event_payload(...)`,
  - expanded emitted quest `added_head` payload rows to carry optional `pos/hp/lifecycle_stage/orbit_angle/orbit_radius/flags/type_id`.
- `src/crimson/sim/driver/replay_events.py`
  - switched quest `creature_spawn` replay handling to full-row parser,
  - applied full optional `added_head` overrides to active creature entries (`pos/heading/target_heading/ai_mode/link_index/hp/lifecycle_stage/orbit/flags/type_id`).
- Tests:
  - `tests/test_original_capture_conversion.py`
  - `tests/test_replay_runners.py`
  - expanded to cover richer `added_head` payload parse + application paths.

### Validation

- Targeted regression tests:
  - `uv run pytest tests/test_original_capture_conversion.py::test_convert_capture_to_replay_emits_quest_creature_spawn_events tests/test_original_capture_conversion.py::test_convert_capture_to_replay_emits_quest_added_head_without_spawn_rows tests/test_replay_runners.py::test_capture_creature_spawn_event_applies_added_head_overrides tests/test_replay_runners.py::test_capture_creature_spawn_event_applies_added_head_without_spawn_rows`
- Frontier probes:
  - `uv run crimson original focus-trace artifacts/frida/share/gameplay_diff_capture.quest_1_8.json --tick 9694 --near-miss-threshold 0.35 --top-rng 10 --near-miss-limit 8 --diff-limit 8 --no-cache --json-out analysis/frida/reports/session20_sweep_current/gameplay_diff_capture.quest_1_8_focus_9694_post_full_added_head_nocache.json`
  - `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 6 --run-summary-short-max-rows 40 --no-cache --json-out analysis/frida/reports/session20_sweep_current/gameplay_diff_capture.quest_1_8_after_added_head_full_override_probe_nocache.json` *(expected non-zero exit while diverged)*
- Repository checks:
  - `just check`

### Outcome / Next Probe

- **Current wall remains:** `quest_1_8 tick 9760` with unchanged missing RNG-tail/hit profile.
- Existing capture data is still insufficient to isolate the first causative arithmetic branch across the full drift ancestry.
- Next recapture should add targeted player+creature movement internals in the `9400..9760` ancestry window (not only head-capped micro rows) so the first precision split can be attributed deterministically.

### Session 17 (continued: creature micro recapture tooling)

- **Capture family:** `artifacts/frida/share/gameplay_diff_capture.quest_*.json`
- **Branch:** `feat/diff-quests`
- **First mismatch progression:**
  - before this tooling update: `quest_1_8 tick 9760 (rng_stream_mismatch)`,
  - after this tooling update: earliest unresolved remains `quest_1_8 tick 9760`.

### Key Findings

- The active gameplay wall is capture quality at the frontier, not missing replay hooks:
  - `quest_1_7` is clean with current code/tooling,
  - `quest_1_8` remains stable at `tick 9760` (`missing_tail=98`), with branch ancestry already traced back to earlier movement precision drift.
- Existing default micro capture settings can saturate per-tick head budgets in dense windows, which obscures first-cause attribution for slot-level drift ancestry.
- Differential tooling should explicitly call out likely head-capped focus ticks and provide a direct recapture path.

### Landed Changes

- `scripts/frida/gameplay_diff_capture.js`
  - added env knobs for targeted creature micro recaptures:
    - `CRIMSON_FRIDA_CREATURE_MICRO_SLOTS`
    - `CRIMSON_FRIDA_CREATURE_MICRO_TICK_START`
    - `CRIMSON_FRIDA_CREATURE_MICRO_TICK_END`
    - `CRIMSON_FRIDA_CREATURE_MICRO_MAX_HEAD_PER_TICK`
  - kept defaults unchanged (always-on micro hooks; default cap `128`) while enabling focused high-detail probes.
- `src/crimson/original/divergence_report.py`
  - investigation leads now flag likely focus-tick micro head-cap saturation when `creature_update_micro_count` reaches configured cap,
  - lead text points directly to recapture knobs and capture docs/playbook paths.
- Docs:
  - `docs/frida/gameplay-diff-capture.md`
  - `docs/frida/differential-playbook.md`
  - documented targeted micro recapture workflow for drift-ancestry investigations.

### Validation

- `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py::test_investigation_leads_flag_focus_micro_head_cap`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_7.json --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 10 --no-cache --json-out analysis/frida/reports/session21/gameplay_diff_capture.quest_1_7_recheck_nocache.json`
- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.quest_1_8.json --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 6 --run-summary-short-max-rows 40 --no-cache --json-out analysis/frida/reports/session21/gameplay_diff_capture.quest_1_8_baseline_nocache_after_fix5.json` *(expected non-zero exit while diverged)*
- `just check`

### Outcome / Next Probe

- Tooling now supports high-signal recaptures for the known wall instead of repeating low-head-budget captures.
- Next required artifact to continue gameplay fixes is a recapture of `quest_1_8` drift ancestry window (`~9400..9760`) using targeted slots + raised micro cap.

### Session 17 (continued: recapture-strategy correction)

- **Capture family:** `artifacts/frida/share/gameplay_diff_capture.quest_*.json`
- **Branch:** `feat/diff-quests`
- **Correction scope:** follow-up on session tooling notes to align with dynamic-capture constraints.

### Key Findings

- Quest captures are not replayable apples-to-apples by absolute tick timeline; gameplay divergence in earlier moments shifts later tick-local events.
- Investigation should therefore track **divergence category/signatures** (for example projectile hit shortfall + RNG tail profile + caller clusters), not fixed tick windows.
- Frida script micro slot/tick override knobs are counterproductive for this workflow and were removed.

### Landed Changes

- `scripts/frida/gameplay_diff_capture.js`
  - removed newly added creature-micro slot/tick/cap env overrides,
  - widened default micro head budget from `128` to `256` for broader parity coverage without per-run tuning.
- `src/crimson/original/divergence_report.py`
  - added `divergence_category` classification output (console + JSON) so investigations can compare mismatches by class/signature across different captures,
  - retained and reframed micro-cap saturation lead as a category-level signal, not a tick-window recapture prescription.
- Docs:
  - `docs/frida/gameplay-diff-capture.md`
  - `docs/frida/differential-playbook.md`
  - updated to emphasize category/signature tracking over absolute tick targeting.

### Outcome / Next Probe

- Continue from the unresolved `quest_1_8` frontier by matching category signatures across new captures:
  - `divergence_category`
  - projectile hit shortfall profile
  - dominant caller clusters near first sustained mismatch.

---
