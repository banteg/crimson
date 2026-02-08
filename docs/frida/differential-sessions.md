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

### Next probe

- Record a new capture with the latest v2 script defaults (`48a07c61`, full-detail tick sampling by default), then rerun divergence to compare `samples.secondary_projectiles`/`samples.creatures` at the first mismatch tick directly.
