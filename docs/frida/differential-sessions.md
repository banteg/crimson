# Differential Capture Sessions

Use this log for every original-vs-rewrite differential capture iteration.
Each entry should capture:

- Which recording was used (path + hash)
- Which verifier command was run
- First mismatch
- Evidence-backed findings
- Fixes landed because of that capture
- Remaining blockers / next probe

## Session template

- **Session ID:** `YYYY-MM-DD-<letter>`
- **Capture:** `<path>`
- **Capture SHA256:** `<sha256>`
- **Verifier command:** `<exact command>`
- **First mismatch:** `tick <n> (<fields>)`

### Findings

- `<finding 1>`
- `<finding 2>`

### Fixes from this session

- `<commit or file change>`
- `<commit or file change>`

### Next probe

- `<what to capture/check next>`

---

## Capture policy (current default)

- Record full-detail v2 captures by default (no focus window, no sample limits).
- Keep `artifacts/frida/share/gameplay_diff_capture_v2.jsonl` as the source artifact and always log SHA256 per session.
- Use `--run-summary` or `--run-summary-short` in divergence reports so each session entry includes a native-run narrative.
- If any env knob is used to throttle capture volume, list the exact knob/value in that session entry.

---

## Session 2026-02-08-a

- **Session ID:** `2026-02-08-a`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 2e-3 --window 24 --lead-lookback 1024 --run-summary --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Findings

- Rewrite awards an extra kill at tick `1794` (`+41 XP`) from the secondary-projectile path; the active rocket transitions to detonation and kills creature slot `25`.
- Native capture reports no `creature_damage`/`creature_death` telemetry at tick `1794`, so the rewrite kill is upstream drift, not just a missing reward mapping.
- Pre-divergence RNG drift is present in creature AI: rewrite consumes `crt_rand` in `creature_ai7_tick_link_timer` on tick `1791` while capture reports `rand_calls=0`; this advances timer/link branches for AI7 spiders before the kill divergence.

### Fixes from this session

- Added optional run narrative output to divergence tooling (`--run-summary`) in `scripts/original_capture_divergence_report.py`.
- Added summary extraction tests in `tests/test_original_capture_divergence_report_summary.py`.
- Added this running session ledger for capture evidence and fix provenance.

### Next probe

- Reconcile AI7 timer/link-index progression against native (`creature_update_all` / `creature_alloc_slot` semantics) to eliminate early RNG drift before tick `1794`.

---

## Session 2026-02-08-b

- **Session ID:** `2026-02-08-b`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 12 --lead-lookback 512 --run-summary --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Findings

- Focus tick `1794` has a large rewrite-only RNG burst: native `rand_calls=2`, rewrite consumes `184` draws.
- Stage attribution isolates almost all rewrite draws to `ws_after_projectiles -> ws_after_secondary_projectiles` (`182` draws), pointing directly at secondary projectile hit/explosion branches.
- Rewrite resolves a kill at tick `1794` (`creature_index=25`, `type_id=2`, `xp_awarded=41`, owner `-1`) while capture reports zero `creature_damage`/`creature_death` events on the same tick.

### Fixes from this session

- Extended `scripts/original_capture_divergence_report.py` to infer rewrite `rand_calls` from RNG marks and print `rand_calls(e/a/d)` in the divergence window.
- Added focus-tick rewrite diagnostics (stage-local RNG call breakdown + rewrite death ledger head) to the report output and JSON payload.
- Added RNG-call inference tests in `tests/test_original_capture_divergence_report_rng_calls.py`.

### Next probe

- Capture a focused run around tick `1794` with entity samples enabled so native projectile/creature positions can be compared directly:
  `CRIMSON_FRIDA_V2_FOCUS_TICK=1794 CRIMSON_FRIDA_V2_FOCUS_RADIUS=64`.

---

## Session 2026-02-08-c

- **Session ID:** `2026-02-08-c`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 16 --lead-lookback 512 --run-summary --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Findings

- Divergence is unchanged at tick `1794`: rewrite resolves a secondary-projectile kill (`creature_index=25`, `xp_awarded=41`) while capture reports no `creature_damage`/`creature_death` events and only two native RNG calls.
- Rewrite-only RNG-on-zero-native ticks (`1590`, `1654`, `1671`, `1673`, `1688`, `1709`, `1710`, `1715`, `1791`) were traced to `creature_ai7_tick_link_timer`.
- Experimental disabling/removal of AI7 timer RNG behavior moved divergence much earlier (`tick 736`), so AI7 timer draws are likely required behavior (or capture tick-boundary attribution), not the primary fix target.

### Fixes from this session

- Added mode-aware input reconstruction for original-capture replays:
  - parse/store `move_mode` + `aim_scheme`,
  - include alternate single-player keybinds,
  - compute `digital_move_enabled_by_player` and emit it in bootstrap payload.
- Updated survival/rush replay runners to decode digital movement keys only when bootstrap enables it for that player.
- Added `--run-summary-short` to `scripts/original_capture_divergence_report.py` for concise native-run highlight output (`bonus/weapon/perk/level/state`), with row-limit knobs.

### Next probe

- Capture a focused run around tick `1794` with entity samples so we can compare native projectile/creature geometry directly at the kill boundary:
  `CRIMSON_FRIDA_V2_FOCUS_TICK=1794 CRIMSON_FRIDA_V2_FOCUS_RADIUS=96`.

---

## Session 2026-02-08-d

- **Session ID:** `2026-02-08-d`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 8 --lead-lookback 256 --run-summary-short --run-summary-short-max-rows 12`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Findings

- The active divergence path is secondary-projectile specific (`secondary_projectiles=182` rewrite-side calls at focus tick), but the capture lacked direct secondary projectile spawn telemetry.
- Non-focused captures also omit per-tick entity samples, which prevents geometry-level comparison at tick `1794` without rerunning the recording.
- This is now a concrete capture-coverage blocker rather than a replay-converter blocker.

### Fixes from this session

- Updated `scripts/frida/gameplay_diff_capture_v2.js` to hook `fx_spawn_secondary_projectile` and emit `secondary_projectile_spawn` events in `event_counts`/`event_heads`.
- Added focused sampling of active `secondary_projectiles` (`samples.secondary_projectiles`) with a dedicated env knob:
  `CRIMSON_FRIDA_V2_SECONDARY_PROJECTILE_SAMPLE_LIMIT`.
- Updated `docs/frida/gameplay-diff-capture-v2.md` to document the new secondary spawn telemetry and sample limit option.

### Next probe

- Record a new focused session using the updated script and include secondary projectile samples:
  `CRIMSON_FRIDA_V2_FOCUS_TICK=1794 CRIMSON_FRIDA_V2_FOCUS_RADIUS=128 CRIMSON_FRIDA_V2_SECONDARY_PROJECTILE_SAMPLE_LIMIT=64`.

---

## Session 2026-02-08-e

- **Session ID:** `2026-02-08-e`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 20 --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Findings

- Divergence is still the same (`tick 1794`, rewrite-only `+182` RNG draws in `secondary_projectiles`, rewrite-only kill worth `+41 XP`).
- This capture still lacks per-tick `samples` rows at the divergence tick, so we still cannot do geometry-level native-vs-rewrite comparison for projectile/creature positions on this recording.
- Ghidra comparison found a concrete secondary homing mismatch: native lock-on uses `creature_find_nearest(origin, -1, 0.0)` semantics (active + `hitbox_size == 16.0`, no HP gate, fallback index `0`), while rewrite still used HP-based candidate gating.

### Fixes from this session

- Updated `src/crimson/projectiles.py` homing secondary target selection to match native nearest-target sentinel behavior (active + hitbox sentinel, no HP gate fallback path).
- Updated secondary projectile scan logic to use `active` checks (native-like) instead of HP-only checks for lock-on/collision candidate filtering, and added explicit `active` guard in detonation radius damage loop.
- Added regression tests in `tests/test_projectiles.py` for native-like homing target sentinel behavior and HP-agnostic active collision scan behavior.
- Updated `scripts/original_capture_divergence_report.py` to surface focus-tick sample coverage (`sample_counts`) and emit an explicit blocker lead when entity samples are missing at divergence ticks, with tests in `tests/test_original_capture_divergence_report_rng_calls.py`.

### Next probe

- Record a new capture with the latest v2 script defaults (`48a07c61`, full-detail tick sampling by default), then rerun divergence to compare `samples.secondary_projectiles`/`samples.creatures` at the first mismatch tick directly.

---

## Session 2026-02-08-f

- **Session ID:** `2026-02-08-f`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 20 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 3504 (players[0].experience, score_xp)`

### Findings

- Rewrite still awards a rewrite-only kill at tick `3504` (`+35 XP`) while native reports `rand_calls=0` and no `creature_damage`/`creature_death` events on that tick.
- Geometry at the focus window confirms native projectile `index 4` (`type_id=6`) travels with angle `0.7043`; rewrite shot angle differs by then because the RNG stream has already drifted.
- Root-cause signal appears earlier: first pre-focus RNG head shortfall is tick `3453` (`expected_head_len=353`, `actual_rand_calls=268`, shortfall `85` draws), which indicates missing rewrite RNG-consuming branches before the XP divergence.
- Tick `3453` still has close creature/projectile state parity in sampled values (including death outcomes), so this shortfall is likely in repeated hit/presentation RNG work (e.g. extra corpse-hit visual/audio branches), not a large state jump.

### Fixes from this session

- Extended `scripts/original_capture_divergence_report.py` with a new investigation lead:
  `Pre-focus RNG-head shortfall indicates missing RNG-consuming branch`.
- The new lead reports:
  - first shortfall tick,
  - expected RNG head length vs rewrite rand calls,
  - missing draw count,
  - dominant native caller_static and resolved native function hints.
- Added regression coverage in `tests/test_original_capture_divergence_report_rng_calls.py` for:
  - shortfall detection helper,
  - lead emission with native function mapping.

### Next probe

- Instrument/compare `projectile_update` hit-loop parity at tick `3453` (Gauss/Fire-Bullets corpse-hit path) to explain the missing pre-focus RNG draws before tick `3504`.

---

## Session 2026-02-08-g

- **Session ID:** `2026-02-08-g`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 20 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 40 --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 3504 (players[0].experience, score_xp)`

### Findings

- Tick `3453` is still the first major RNG parity break (`expected rand_calls=353`, rewrite `268`, shortfall `85`).
- Rewrite hit stream at tick `3453` currently resolves `4` projectile hits (all Gauss) with `2` damage kills; native RNG caller totals imply at least one additional non-damaging hit-resolution branch in `projectile_update` (likely corpse-hit path).
- Existing capture telemetry does not directly encode native projectile hit-resolve rows, so we cannot conclusively assign that missing branch to a specific creature/index from this recording alone.

### Fixes from this session

- Updated `scripts/frida/gameplay_diff_capture_v2.js` to hook `creature_find_in_radius` when called from `projectile_update` and emit:
  - `event_counts.projectile_find_hit`,
  - `event_heads.projectile_find_hit` rows (includes `creature_index`, query radius/pos, caller, and `corpse_hit` flag),
  - per-tick caller buckets in diagnostics (`top_projectile_find_hit_callers`).
- Extended `scripts/original_capture_divergence_report.py` to ingest and surface this telemetry:
  - window table now includes `p_hits(e/a)` (`capture projectile_find_hit` vs rewrite `events.hit_count`),
  - new lead: `Native projectile hit resolves exceed rewrite hit events`,
  - focus debug now prints projectile hit-resolve count/head/corpse count.
- Added regression tests in `tests/test_original_capture_divergence_report_rng_calls.py` for:
  - projectile hit shortfall helper detection,
  - lead emission for projectile hit shortfalls.
- Updated `docs/frida/gameplay-diff-capture-v2.md` with the new projectile hit telemetry semantics.

### Next probe

- Record a new capture with the updated v2 script, then re-run divergence and inspect the first `projectile_find_hit` shortfall tick to isolate the exact missing corpse-hit path in `src/crimson/projectiles.py`.

---

## Session 2026-02-08-h

- **Session ID:** `2026-02-08-h`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 20 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 20 --json-out analysis/frida/divergence_report_latest.json`
  - `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3453.json`
  - `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3412 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3412.json`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)`

### Findings

- Focus trace at tick `3453` confirms rewrite RNG draw profile is dominated by Gauss/Fire-Bullets decal streak calls:
  - `queue_large_hit_decal_streak` + `fx_queue.add_random` callsites account for the bulk of `268` draws.
  - Collision trace shows `4` resolved hits and two near-miss checks on creature `19` (margins `+0.0888` and `+0.1594`), consistent with a native-only extra corpse/edge hit branch candidate.
- A stronger upstream drift signal appears earlier than the XP mismatch:
  - at tick `3412`, indexed sample comparison shows creature slot divergence (`index 22` active in capture but inactive/repurposed in rewrite), with large position/HP deltas.
  - This indicates hidden per-index world drift before the first checkpoint-field mismatch at tick `3504`.

### Fixes from this session

- Added `scripts/original_capture_focus_trace.py`, a focused per-tick debugger that replays to a target tick and reports:
  - rewrite RNG callsite distribution (`rand` caller stack buckets),
  - collision predicate hits and near-miss candidates (`margin` diagnostics from `_within_native_find_radius`),
  - indexed sample diffs against capture (`creatures`/`projectiles`) to expose slot-level drift.
- Updated `docs/frida/gameplay-diff-capture-v2.md` with usage for the new focus trace workflow.

### Next probe

- Run the next capture with updated v2 Frida hooks (now including `projectile_find_hit`) and use:
  - divergence report for the first RNG shortfall tick,
  - focus trace at that tick and nearby onset tick for slot-index drift,
  to isolate whether the missing draw path is a pure projectile corpse-hit branch or an earlier creature-slot lifecycle mismatch.

---

## Session 2026-02-08-i

- **Session ID:** `2026-02-08-i`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 4096 --run-summary-short --run-summary-short-max-rows 80 --json-out analysis/frida/divergence_report_latest.json`
  - `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 4096 --focus-tick 3453 --json-out analysis/frida/divergence_report_focus3453_latest.json`
  - `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3453_latest.json`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)`

### Findings

- Tick `3453` remains the first major shortfall (`native rand_calls=353`, rewrite `268`, missing `85`).
- New focus-trace RNG value alignment confirms this is a pure late-tick branch omission:
  - `prefix_match=268` (all rewrite draw values exactly match native prefix),
  - native has an extra `85`-draw tail after rewrite stops.
- Native-only tail callers are dominated by `projectile_update`/decal paths:
  - `0x0042176f`, `0x0042184c`, `0x00427760`, `0x0042778e`, `0x004277b0`, `0x0042780b` (all `x9` in the missing tail),
  - plus smaller `0x00421799`, `0x004217c6`, `0x0042ebc0..0x0042ec44` buckets.
- This pattern is consistent with missing additional Gauss/Fire-Bullets hit-resolution presentation work (likely extra corpse-hit branches) rather than wrong RNG values in already-executed branches.
- A float32 collision/math probe in rewrite did not change the shortfall (`3453` stayed `353/268`), so the issue is not trivially fixed by local f32 rounding in `_within_native_find_radius`.

### Fixes from this session

- Extended `scripts/original_capture_focus_trace.py` with `rng_value_alignment` diagnostics:
  - capture/rewrite draw counts,
  - exact value prefix-match length,
  - first mismatch index/value (when present),
  - native-only tail caller buckets,
  - missing-tail preview rows with inferred rewrite callsites.
- Added regression tests in `tests/test_original_capture_focus_trace.py` for RNG alignment summary behavior.
- Updated `docs/frida/gameplay-diff-capture-v2.md` to document the new focus-trace RNG alignment section.

### Next probe

- Fix capture-side projectile hit telemetry reliability for these runs (`capture_projectile_find_hit_count` is still `0` at the shortfall tick despite clear native RNG tail evidence), then re-record.
- After a capture with non-zero projectile hit rows at the shortfall tick, compare native hit-resolve sequence against rewrite to patch the exact missing corpse-hit path in `src/crimson/projectiles.py`.

---

## Session 2026-02-08-j

- **Session ID:** `2026-02-08-j`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - baseline:
    `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_latest.json`
  - precision-parity run:
    `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch.json`
  - focus trace after precision patch:
    `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3453_precision_patch.json`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)` (unchanged)

### Findings

- Baseline and precision-patch runs still diverge at the same earliest points:
  - first pre-focus RNG shortfall remains `tick 3453` (`expected_head_len=353`, rewrite `268`, missing `85`),
  - first checkpoint-field mismatch remains `tick 3504` (`players[0].experience`, `score_xp`, `+35 XP`).
- Dominant native caller buckets at the shortfall tick are unchanged and still concentrated in Fire-Bullets decal/random FX paths:
  - `0x0042176f`, `0x0042184c`, `0x00427760`, `0x0042778e`, `0x004277b0`, `0x0042780b` (all `x30` in the shortfall view).
- Focus-trace RNG alignment is still a perfect prefix + missing tail:
  - `prefix_match=268`, `missing_native_tail=85`.
- Precision slice moved creature geometry, but not in a beneficial direction for the known near-miss boundary:
  - tick `3453`, creature `19`, substep `57` near-miss margin changed from `+0.0888205` (baseline) to `+0.0991395` (after patch),
  - indexed drift for creature `19` changed from `x_delta=-0.116419` to `x_delta=-0.126840`.

### Fixes from this session

- Added a dedicated parity helper module:
  - `src/crimson/math_parity.py` (`f32`, native angle constants, controlled heading/trig wrappers).
- Applied float32-boundary movement/heading math in creature AI + runtime movement path:
  - `src/crimson/creatures/ai.py`,
  - `src/crimson/creatures/runtime.py`.
- Added regression tests for parity helpers and AI quantization boundaries:
  - `tests/test_math_parity.py`,
  - updated `tests/test_creature_ai.py`.

### Validation

- `uv run pytest tests/test_math_parity.py tests/test_creature_ai.py tests/test_energizer_bonus.py tests/test_creature_runtime.py`
- `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_capture_focus_trace.py`

### Next probe

- Keep this math-parity slice as groundwork, but pivot the next increment to a narrower branch-level investigation at tick `3453`:
  - compare native vs rewrite hit-resolve sequencing around Fire-Bullets/Gauss decal emission (`queue_large_hit_decal_streak` + `fx_queue_add_random`) and validate whether rewrite misses a corpse/secondary resolve branch independent of movement precision.

---

## Session 2026-02-08-k

- **Session ID:** `2026-02-08-k`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - dead-state parity run:
    `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch3.json`
  - focus trace after dead-state parity run:
    `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3453_precision_patch3.json`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)` (unchanged)

### Findings

- Dead-state f32 parity changes did not shift the earliest divergence points:
  - first pre-focus RNG shortfall remains `tick 3453` (`expected_head_len=353`, rewrite `268`, missing `85`),
  - first checkpoint-field mismatch remains `tick 3504` (`players[0].experience`, `score_xp`, `+35 XP`).
- Dominant native caller buckets at the shortfall tick are unchanged:
  - `0x0042176f`, `0x0042184c`, `0x00427760`, `0x0042778e`, `0x004277b0`, `0x0042780b` (all `x30` in the shortfall view).
- Focus-trace alignment remains a perfect prefix + missing tail:
  - `prefix_match=268`, `missing_native_tail=85`.
- Known near-miss boundary still moved in the wrong direction for the missing hit candidate:
  - tick `3453`, creature `19`, substep `57` margin is `+0.0991395` (vs `+0.0888205` in baseline).

### Fixes from this session

- Tightened dead-creature hitbox transition and decay math to float32 boundaries in `src/crimson/creatures/runtime.py`.
- Updated dead-slide velocity/position update to use explicit float32 heading/trig conversion and float32 stores.
- Removed dead-slide world clamp in the dead branch to match native `creature_update_all` flow.

### Validation

- `uv run ruff check src/crimson/creatures/runtime.py`
- `uv run pytest tests/test_creature_runtime.py tests/test_creature_ai.py tests/test_math_parity.py tests/test_energizer_bonus.py`
- `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_capture_focus_trace.py`
- `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch3.json`
- `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3453_precision_patch3.json`

### Next probe

- Keep the dead-state parity patch as groundwork, then patch one narrow hit-resolve branch in `src/crimson/projectiles.py` to recover the missing fifth hit at tick `3453` (creature `19`, substep `57`) before iterating on broader movement precision again.

---

## Session 2026-02-08-l

- **Session ID:** `2026-02-08-l`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - divergence check:
    `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch5.json`
  - focus trace with enhanced diagnostics:
    `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3453_precision_patch5b.json`
  - slot trajectory replay:
    `uv run python scripts/original_capture_creature_trajectory.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --creature-index 19 --start-tick 2150 --end-tick 3453 --inter-tick-rand-draws 1 --json-out analysis/frida/creature19_trajectory_2150_3453_patch5.json`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)` (unchanged)

### Findings

- Earliest divergence points are unchanged:
  - first pre-focus RNG shortfall still `tick 3453` (`expected_head_len=353`, rewrite `268`, missing `85`),
  - first checkpoint mismatch still `tick 3504` (`players[0].experience`, `score_xp`, `+35 XP`).
- Focus trace still shows exact rewrite-vs-native RNG prefix parity (`prefix_match=268`) followed by a native-only tail (`85` draws), so this remains a missing late-tick branch rather than wrong RNG values in shared paths.
- New inferred-tail buckets identify the missing branch mix more concretely:
  - dominated by `queue_large_hit_decal_streak` + `fx_queue.add_random` callsites,
  - plus smaller `spawn_blood_splatter` tail buckets.
- New per-hit hook rows confirm rewrite currently handles exactly `4` Gauss decal hooks at tick `3453` (`rng_draws=44,44,38,40`), which is consistent with missing additional native hit-resolution presentation work after rewrite stops drawing.
- Creature slot `19` trajectory remains an accumulated alive-path drift (first drift >= `0.01` at tick `2519`, max `0.138328` at tick `3362`, no AI mode transitions), reinforcing that local trig precision probes did not address the shortfall mechanism.

### Fixes from this session

- Extended `scripts/original_capture_creature_trajectory.py` with richer capture-vs-rewrite state fields (`flags`, `target_player`, `ai_mode`, heading/attack/move-scale fields) and explicit AI/target transition reporting.
- Extended `scripts/original_capture_focus_trace.py` with:
  - inferred rewrite callsite buckets for the native-only RNG tail,
  - per-hit decal hook rows (`handled`, `type_id`, per-hit RNG draw count, target position),
  - JSON output for these new diagnostics.

### Validation

- `uv run ruff check scripts/original_capture_focus_trace.py scripts/original_capture_creature_trajectory.py`
- `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_capture_focus_trace.py`

### Next probe

- Patch one narrow `projectile_update`/post-hit parity slice to recover missing late-tick hit-resolution work at tick `3453`:
  - compare rewrite hit/decal loop sequencing against the native tail mix (`queue_large_hit_decal_streak`, `fx_queue_add_random`, `spawn_blood_splatter`),
  - focus first on extra corpse/non-damaging hit resolve branches that can consume RNG without changing sampled world state immediately.

---

## Session 2026-02-08-m

- **Session ID:** `2026-02-08-m`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - focus trace with caller-gap diagnostics:
    `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --top-rng 20 --diff-limit 12 --json-out analysis/frida/focus_trace_tick3453_precision_patch6b.json`
  - divergence check (non-zero exit on divergence is expected):
    `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch7.json`
  - tooling validation:
    `uv run pytest tests/test_original_capture_focus_trace.py tests/test_original_capture_divergence_report_rng_calls.py`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)` (unchanged)

### Findings

- Earliest divergence points remain unchanged:
  - first pre-focus RNG shortfall still `tick 3453` (`expected_head_len=353`, rewrite `268`, missing `85`),
  - first checkpoint mismatch still `tick 3504` (`players[0].experience`, `score_xp`, `+35 XP`).
- New focus-trace caller-gap diagnostics now quantify the shortfall in branch-level units:
  - Fire-Bullets/Gauss loop-seed caller (`0x0042176f`) counts are `capture=30`, `rewrite=24`, gap `6`.
  - With native loop width fixed at `6` iterations per handled hit, this is exactly **one missing hit-equivalent decal loop**.
  - Matching `+6` gaps appear for `0x0042184c` and each `fx_queue_add_random` RNG caller (`0x00427760/8e/b0/0b`), reinforcing the same single-hit deficit.
- Blood-splatter RNG caller counts (`0x0042ebc0/ebe3/ec00/ec1d/ec44`) show `capture=24`, `rewrite=16`, gap `8`, consistent with missing post-hit presentation work tied to that same missed resolution path.
- Collision evidence at tick `3453` remains unchanged: projectile `3` near-misses creature `19` at substep `57` with margin `+0.0991395`, which aligns with the one-missing-hit interpretation.

### Fixes from this session

- Extended `scripts/original_capture_focus_trace.py` with native-vs-rewrite caller-count parity diagnostics:
  - per-caller capture/rewrite count gaps with native caller labels,
  - Fire-Bullets loop parity summary (`capture/rewrite iterations`, `missing iterations`, `estimated missing hits`),
  - JSON output fields for these new diagnostics.
- Added regression coverage in `tests/test_original_capture_focus_trace.py` for caller-gap and Fire-Bullets loop-parity inference helpers.

### Validation

- `uv run pytest tests/test_original_capture_focus_trace.py tests/test_original_capture_divergence_report_rng_calls.py`
- `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --top-rng 20 --diff-limit 12 --json-out analysis/frida/focus_trace_tick3453_precision_patch6b.json`
- `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch7.json` *(expected non-zero exit while diverged)*

### Next probe

- Use the new Fire-Bullets loop parity metric as the primary acceptance target for the next sim patch:
  - reduce `seed_iterations` gap at tick `3453` from `6` to `0`,
  - confirm rewrite reaches `5` handled Gauss/Fire-Bullets decal hooks at that tick (from current `4`),
  - then re-run divergence to check whether the first checkpoint mismatch moves past tick `3504`.

---

## Session 2026-02-08-n

- **Session ID:** `2026-02-08-n`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - focus trace after truncation cleanup:
    `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --top-rng 20 --diff-limit 12 --json-out analysis/frida/focus_trace_tick3453_precision_patch11_truncation_cleanup.json`
  - divergence check after truncation cleanup:
    `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch11_truncation_cleanup.json`
  - movement/parity validation:
    `uv run pytest tests/test_math_parity.py tests/test_creature_ai.py tests/test_creature_runtime.py tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_capture_focus_trace.py`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)` (unchanged)

### Findings

- This truncation-boundary cleanup did not move the earliest divergence points:
  - first pre-focus RNG shortfall remains `tick 3453` (`expected_head_len=353`, rewrite `268`, missing `85`),
  - first checkpoint mismatch remains `tick 3504` (`players[0].experience`, `score_xp`, `+35 XP`).
- Fire-Bullets loop parity is unchanged:
  - `seed_iterations capture=30 rewrite=24 missing=6` (still one missing hit-equivalent loop).
- The known near-miss boundary is effectively unchanged:
  - tick `3453`, projectile `3`, creature `19`, substep `57`, margin `+0.099141`.
- Creature drift distribution shifted slightly but not materially:
  - creature `19` remains `x_delta=-0.126840` at tick `3453`.

### Fixes from this session

- Reduced excess intermediate float32 truncation in movement/heading parity helpers and AI targeting chains:
  - `src/crimson/math_parity.py`
    - switched native constants to exact float32 bit patterns,
    - collapsed heading/trig chains to one float32 store boundary where appropriate.
  - `src/crimson/creatures/ai.py`
    - removed intermediate float32 truncation in `_orbit_target_f32`,
    - removed intermediate float32 truncation in AI6 orbit target calculation.
  - `src/crimson/creatures/runtime.py`
    - kept intermediate math in `_angle_approach`, `_movement_delta_from_heading_f32`, and `_velocity_from_delta_f32` in higher precision, with float32 stores at state boundaries.

### Validation

- `uv run ruff check src/crimson/math_parity.py src/crimson/creatures/ai.py src/crimson/creatures/runtime.py`
- `uv run pytest tests/test_math_parity.py tests/test_creature_ai.py tests/test_creature_runtime.py tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_capture_focus_trace.py`
- `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --top-rng 20 --diff-limit 12 --json-out analysis/frida/focus_trace_tick3453_precision_patch11_truncation_cleanup.json`
- `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch11_truncation_cleanup.json`

### Next probe

- Pivot from broad movement precision tweaks to the earliest missed-hit path itself at tick `3453`:
  - instrument `projectile_update` hit-resolve ordering around corpse/non-corpse handling in `src/crimson/projectiles.py`,
  - verify whether rewrite skips one native-equivalent Gauss hit resolve that drives `queue_large_hit_decal_streak`/`fx_queue_add_random` tail calls.

---

## Session 2026-02-08-o

- **Session ID:** `2026-02-08-o`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Primary commands:**
  - focus trace for orbit-phase rounding variants:
    `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --top-rng 20 --diff-limit 12 --json-out analysis/frida/focus_trace_tick3453_precision_patch14_orbit_phase_mul_order.json`
  - divergence check for selected variant:
    `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch15_orbit_phase_order_only.json`
  - focused trajectory context:
    `uv run python scripts/original_capture_creature_trajectory.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --creature-index 19 --start-tick 0 --end-tick 3453 --inter-tick-rand-draws 1 --json-out analysis/frida/creature19_trajectory_0_3453_patch11.json`
- **First verifier mismatch:** `tick 3504 (players[0].experience, score_xp)` (unchanged)

### Findings

- Changing AI orbit-phase rounding order materially reduced the known tick-3453 miss geometry but did not yet flip it:
  - creature `19` drift at tick `3453` improved from `x_delta=-0.126840` to `x_delta=-0.061776`,
  - near-miss margin improved from `+0.099141` to `+0.034608` (still a miss).
- Earliest divergence points are still unchanged:
  - pre-focus RNG shortfall remains `tick 3453` (`expected_head_len=353`, rewrite `268`, missing `85`),
  - first checkpoint mismatch remains `tick 3504` (`players[0].experience`, `score_xp`, `+35 XP`).
- Fire-Bullets loop parity still indicates one missing hit-equivalent loop at the shortfall tick:
  - `seed_iterations capture=30 rewrite=24 missing=6`.

### Fixes from this session

- Updated AI movement-target prep in `src/crimson/creatures/ai.py`:
  - changed orbit-phase construction to mirror native-like intermediate rounding order:
    - from `f32(seed * 3.7 * pi)` style
    - to `f32(seed * 3.7f) * pi` style,
  - removed float32 truncation of `_distance_f32` intermediate distance before threshold checks.

### Validation

- `uv run ruff check src/crimson/creatures/ai.py`
- `uv run pytest tests/test_creature_ai.py tests/test_math_parity.py`
- `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3453 --near-miss-threshold 0.35 --top-rng 20 --diff-limit 12 --json-out analysis/frida/focus_trace_tick3453_precision_patch14_orbit_phase_mul_order.json`
- `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_precision_patch15_orbit_phase_order_only.json`

### Next probe

- Continue reducing the remaining `+0.0346` near-miss gap with similarly narrow movement-heading rounding adjustments, then re-check whether tick `3453` gains the missing fifth hit.
- In parallel, add hit-resolve sequence instrumentation in `src/crimson/projectiles.py` for the tick-3453 path to rule out a logic-order mismatch independent of geometry.

---

## Session 2026-02-09-p

- **Session ID:** `2026-02-09-p`
- **Capture:** `n/a (tooling update only; no new recording in this session)`
- **Capture SHA256:** `n/a`
- **Primary commands:**
  - tooling validation:
    `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_capture_focus_trace.py`
  - lint validation:
    `uv run ruff check scripts/original_capture_divergence_report.py`
- **First verifier mismatch:** `n/a`

### Findings

- Absolute tick windows are poor cross-session anchors because runs diverge in event chronology and RNG consumption even when the underlying root cause is unchanged.
- We need RNG-order anchors (`global seq`, per-tick local call index, seed epoch) directly in capture output so later analysis can align by call order rather than by wall-clock tick.

### Fixes from this session

- Upgraded `scripts/frida/gameplay_diff_capture_v2.js` RNG diagnostics:
  - every captured tick now stores RNG call sequence metadata (`seq`, `tick_call_index`, seed epoch, mirrored CRT state transitions) in `rng.head` and `checkpoint.rng_marks`.
  - between-tick RNG draws are tracked and carried into the next tick (`outside_before_*`) so boundary activity is visible.
  - added optional per-roll event emission (`event: "rng_roll"`) via `CRIMSON_FRIDA_V2_RNG_ROLL_LOG=1`, with cap control (`CRIMSON_FRIDA_V2_MAX_RNG_ROLL_LOG_EVENTS`).
  - added mirrored CRT state integrity tracking (`CRIMSON_FRIDA_V2_RNG_STATE_MIRROR`, mismatch counters) and exposed counters in heartbeat output.
- Extended `scripts/original_capture_divergence_report.py` to ingest and surface new RNG sequence metadata:
  - raw tick debug now captures seq range + seed epoch + outside-before counters,
  - pre-focus RNG shortfall lead now reports sequence/epoch anchors,
  - focus debug output now prints capture RNG sequence range and mirror mismatch totals.
- Updated `docs/frida/gameplay-diff-capture-v2.md` with the new RNG trace fields/knobs and a “full RNG divergence trace profile”.

### Next probe

- Record a new session using the full RNG trace profile:
  - `CRIMSON_FRIDA_V2_RNG_ROLL_LOG=1`
  - `CRIMSON_FRIDA_V2_MAX_RNG_ROLL_LOG_EVENTS=-1`
  - `CRIMSON_FRIDA_V2_RNG_HEAD=-1`
  - `CRIMSON_FRIDA_V2_RNG_CALLERS=-1`
  - `CRIMSON_FRIDA_V2_RNG_OUTSIDE_TICK_HEAD=-1`
  - `CRIMSON_FRIDA_V2_RNG_STATE_MIRROR=1`
- Re-run divergence report on that capture and anchor the first shortfall by `seq_first/seq_last` instead of treating raw tick numbers as cross-session comparable.
