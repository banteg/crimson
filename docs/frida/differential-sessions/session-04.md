---
tags:
  - frida
  - differential-sessions
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

