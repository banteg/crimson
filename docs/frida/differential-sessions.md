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
