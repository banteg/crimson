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

- Default to full-detail `gameplay_diff_capture_v2` captures (no focus window, no sample limits).
- Keep `artifacts/frida/share/gameplay_diff_capture_v2.jsonl` as the canonical artifact and always log SHA256.
- Use `--run-summary` or `--run-summary-short` in divergence reports.
- If any env knobs throttle capture volume, log exact knob/value.
- If capture SHA is unchanged, update the existing session; do not create a new one.

---

## Session 1 (2026-02-08)

- **Legacy IDs:** `2026-02-08-a` .. `2026-02-08-e`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Baseline verifier command:**
  `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 20 --json-out analysis/frida/divergence_report_latest.json`
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
- Added v2 capture telemetry:
  - secondary projectile spawn hooks and secondary sample capture.
- Landed gameplay parity patch in `src/crimson/projectiles.py` for native-like secondary homing target semantics (active + hitbox sentinel behavior).

### Outcome / Next Probe

- Session closed when a new recording moved divergence to a later and different profile (`tick 3504` on next SHA), indicating this capture family had been exhausted.

---

## Session 2 (2026-02-08)

- **Legacy IDs:** `2026-02-08-f` .. `2026-02-08-o`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `251b2ef83c9ac247197fbce5f621e1a8e3e47acb7d709cb3869a7123ae651cd6`
- **Baseline verifier command:**
  `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 30 --json-out analysis/frida/divergence_report_latest.json`
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
  - `scripts/original_capture_focus_trace.py` (callsite RNG, collision near-miss, indexed sample diffs).
  - RNG value-alignment and native-only tail diagnostics.
  - caller-gap and loop-parity summaries.
  - `scripts/original_capture_creature_trajectory.py` enhancements for long-horizon slot drift.
- Added v2 telemetry for projectile-hit resolution (`projectile_find_hit`, corpse-hit markers).
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

- Upgraded `scripts/frida/gameplay_diff_capture_v2.js` RNG diagnostics:
  - per-roll sequence metadata, between-tick carry, optional full roll log, CRT mirror integrity counters.
- Extended `scripts/original_capture_divergence_report.py` to surface sequence/epoch anchors and mirror totals.
- Updated `docs/frida/gameplay-diff-capture-v2.md` with full RNG trace profile guidance.

### Outcome / Next Probe

- Prepared instrumentation for the next capture family; no gameplay parity fix in this session.

---

## Session 4 (2026-02-09)

- **Legacy IDs:** `2026-02-09-q`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `28b8db6eb6b679455dad7376ef76149d26fdd7339dea246518685938cdb48662`
- **Baseline verifier command:**
  `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 40 --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch progression:**
  - initial: `tick 1069 (players[0].ammo)`
  - after replay/input + movement fixes: `tick 3882 (players[0].experience, score_xp)`
  - after capture-RNG map + timer/reload parity fixes: `tick 4421 (players[0].ammo, players[0].weapon_id)`

### Key Findings

- Early divergence (`tick 1069`) was driven by replay input reconstruction mismatch (rewrite firing where native did not).
- `tick 3624` “missing perk RNG” was a tooling false-positive: those draws happened in replay events, outside world-step RNG marks.
- Per-tick `rng.outside_before_calls` replay must special-case tick 0 (bootstrap draws already baked into inferred seed).
- Native `bonus_update` clamps `double_xp/freeze` to `0.0` when timer `<= 0.0`; missing this caused `-8ms` carry and `tick 4311` timer drift.
- Reload timing is float-boundary sensitive: using float32-style reload math plus native preload ordering moved ammo parity to native at `tick 4396`.
- Current blocker is now earlier than the old `3882` kill miss:
  - a weapon bonus spawned at `tick 4150` has a position offset in rewrite (capture `427.1736,548.0906`, rewrite `427.8498,547.4852`),
  - this shifts pickup timing one frame earlier (`tick 4421` vs native `4422`) and cascades into weapon/ammo state divergence.

### Landed Changes

- `fix(gameplay): mirror float32 movement store boundaries` (`da0a12de`)
- `fix(replay): align v2 capture input and perk reconstruction` (`d9f6815e`)
  - improved fire fallback semantics
  - frame-dt precision preference
  - inferred perk menu/pending event reconstruction
- `fix(creatures): round ai7 timer dt_ms to native boundary` (`bb88cfa8`)
- Added event-phase RNG checkpoint marks and event-aware divergence accounting in replay runners/reporting.
- Extended focus-trace RNG interception to cached pool RNG hooks (`particles._rand`, `sprite_effects._rand`).
- Added v2 parser support for `rng.outside_before_calls` and wired per-tick outside-draw replay.
- Patched `bonus_update` timer clamp semantics for `double_experience` and `freeze`.
- Patched reload timing semantics in `player_update` (native preload ordering + float32-style reload timer arithmetic + anxious-loader tail behavior).
- `docs(frida): renumber sessions and fold same-sha updates` (`90f5637e`)

### Validation

- `uv run pytest tests/test_player_update.py tests/test_original_capture_conversion.py tests/test_replay_perk_menu_open_event.py tests/test_creature_runtime.py`
- `uv run python scripts/original_capture_focus_trace.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --tick 3624 --near-miss-threshold 0.35 --json-out analysis/frida/focus_trace_tick3624_latest.json`
- `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 24 --lead-lookback 2048 --run-summary-short --run-summary-short-max-rows 40 --json-out analysis/frida/divergence_report_latest.json` *(expected non-zero exit while diverged)*

### Outcome / Next Probe

- Resolve bonus spawn position parity at `tick 4150` (creature-death position path feeding `BonusPool.try_spawn_on_kill`).
- Re-run divergence after spawn-position fix to see whether legacy `tick 3882` projectile/XP mismatch still remains or was superseded by the earlier pickup-timing drift.
