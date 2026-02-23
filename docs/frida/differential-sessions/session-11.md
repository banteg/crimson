---
tags:
  - frida
  - differential-sessions
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

