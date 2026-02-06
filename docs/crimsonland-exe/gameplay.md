---
tags:
  - status-analysis
---

# Gameplay glue
This page captures high-level gameplay glue that is not already covered by the
standalone data tables.

## Player update (player_update / FUN_004136b0)

`player_update` runs once per player during the main gameplay loop when
`game_state_id` (`DAT_00487270`) == `9`. It handles:

- Per-player movement and aim updates.
- Weapon firing and reload timers.
- Spawning projectiles and effects tied to the active weapon.
- Applying status timers (bonus/perk effects).

### Per-player runtime fields (partial)

These are the most important per-player arrays that bridge weapons, perks, and
bonuses (stride `0xd8`, base `player_health` / `DAT_004908d4`). See
[Player struct](../structs/player.md) for offsets and related fields.

| Offset | Symbol | Meaning | Source / Notes |
| --- | --- | --- | --- |
| `0x294` | `player_spread_heat` | spread/heat | decays each frame; Sharpshooter alters decay and disables per-shot heat gain |
| `0x29c` | `player_weapon_id` | current weapon id | set by `weapon_assign_player` |
| `0x2a0` | `player_clip_size` | clip size | from weapon table, modified by Ammo Maniac + My Favourite Weapon |
| `0x2a8` | `player_ammo` | current ammo | reset to clip size when reload completes |
| `0x2ac` | `player_reload_timer` | reload timer | decremented each frame; used by Angry/Anxious/Stationary Reloader |
| `0x2b0` | `player_shot_cooldown` | shot cooldown | decremented each frame; slowed by Weapon Power Up timer |
| `0x2b4` | `player_reload_timer_max` | reload timer max | used to compute reload progress (HUD + Angry Reloader) |
| `0x2dc` | `player_aim_heading` | aim heading (radians) | used for projectile direction + overlays |
| `0x2f0` | `player_speed_bonus_timer` | speed bonus timer | Bonus id 13 (Speed) |
| `0x2f4` | `player_shield_timer` | shield timer | Bonus id 10 (Shield) |
| `0x2f8` | `player_fire_bullets_timer` | Fire Bullets timer | Bonus id 14 (Fire Bullets) |

Alt-weapon swap caches live in the same struct (offsets `0x2b8..0x2d0`); see
[Weapon table](../weapon-table.md) for the current field map.

Global bonus timers used by `player_update` and the main loop:

| Symbol | Meaning | Source |
| --- | --- | --- |
| `bonus_weapon_power_up_timer` | Weapon Power Up timer | Bonus id 4 |
| `bonus_reflex_boost_timer` | Reflex Boost timer | Bonus id 9 |
| `bonus_energizer_timer` | Energizer timer | Bonus id 2 |
| `bonus_double_xp_timer` | Double XP timer | Bonus id 6 |
| `bonus_freeze_timer` | Freeze timer | Bonus id 11 |
| `time_scale_active` / `time_scale_factor` | time-scale active + factor | driven by Reflex Boost |

### Recovered gameplay helper globals

- `player_alt_weapon_swap_cooldown_ms` (`DAT_0048719c`)
  - Reload-key debounce for Alternate Weapon swapping (`200ms` lockout per swap).
- `perk_jinxed_proc_timer_s` (`_DAT_004aaf1c`)
  - Jinxed perk proc timer reseeded in `perks_update_effects`.
- `perk_man_bomb_trigger_interval_s` / `perk_fire_cough_trigger_interval_s` /
  `perk_hot_tempered_trigger_interval_s` (`_DAT_00473310/14/18`)
  - Trigger thresholds used against `player_man_bomb_timer`, `player_fire_cough_timer`,
    and `player_hot_tempered_timer`.
- `survival_reward_weapon_guard_id` (`DAT_00486fb8`)
  - Guard id used by Survival handout logic (`0x18`/`0x19`) and checked during world render to
    revoke temporary handout weapons.
- `quest_spawn_stall_timer_ms` (`DAT_004c3654`)
  - Quest fallback timer in `quest_spawn_timeline_update` when creatures remain active.
- `perk_lean_mean_exp_tick_timer_s` (`_DAT_004808a4`)
  - Lean Mean Exp Machine cadence timer; `perks_update_effects` resets it to `0.25s` on each tick.
- `perk_doctor_target_creature_id` (`DAT_00487268`)
  - Cached Doctor target creature id for the HUD target-health overlay (`-1` when inactive).
- `quest_stage_banner_timer_ms` (`DAT_00487244`)
  - Quest stage title-card fade timer (incremented in `quest_mode_update`, reset on quest start).
- `player_spread_damping_scalar` (`0x00473a40`)
  - Shared spread-recovery multiplier used by both `player_update` and
    `player_fire_weapon` (eased/clamped between `0.3` and `1.0`).
- `demo_trial_overlay_active` / `demo_trial_overlay_alpha_ms` (`DAT_00480850` / `DAT_00480898`)
  - Demo trial warning overlay latch + fade accumulator (`0..1000`) around `demo_trial_overlay_render`.
- `pause_keybind_help_alpha_ms` (`DAT_00487284`)
  - Pause keybind-help overlay fade accumulator (`0..1000`) used by `ui_render_keybind_help`.
- `player_overlay_suppressed_latch` (`0x0048727c`)
  - Overlay suppression gate checked by `player_render_overlays`; set on
    highscore-return path and cleared by `gameplay_reset_state`.
- `time_played_ms` (`DAT_0048718c`)
  - Registry-backed cumulative playtime counter (`timePlayed`) incremented during active gameplay.

### Bonus HUD slots (active bonus list)

`bonus_apply` registers timed bonuses in the HUD list via `bonus_hud_slot_activate`, and
`bonus_hud_slot_update_and_render` renders up to 16 active slots using the following fields:

- `bonus_hud_slot_active` — per-slot active flag (stride `0x20` bytes).
- `bonus_hud_slot_y` — slide/position accumulator for the slot.
- `bonus_hud_slot_timer_ptr` — pointer to the primary timer (global or per‑player).
- `bonus_hud_slot_alt_timer_ptr` — optional pointer to the player‑2 timer.
- `bonus_hud_slot_label` — string label for the bonus.
- `bonus_hud_slot_icon_id` — icon id used to select a frame from `bonuses.png`.

Recovered bonus label/icon globals used by `bonus_apply`:

- `bonus_label_reflex_boost` / `bonus_icon_reflex_boost`
- `bonus_label_weapon_power_up` / `bonus_icon_weapon_power_up`
- `bonus_label_speed` / `bonus_icon_speed`
- `bonus_label_freeze` / `bonus_icon_freeze`
- `bonus_label_shield` / `bonus_icon_shield`
- `bonus_label_fire_bullets` / `bonus_icon_fire_bullets`
- `bonus_label_energizer` / `bonus_icon_energizer`
- `bonus_label_double_experience` / `bonus_icon_double_experience`
- `bonus_label_points` plus `bonus_label_format_buffer` are used by
  `bonus_label_for_entry` for dynamic “weapon” / “points” label formatting.

### Perk-triggered projectile spawns (player_update)

`player_update` owns several perk timers that spawn projectiles or FX when the
timer crosses its threshold:

- **Man Bomb** (`DAT_004c2c24`): uses `player_man_bomb_timer` (`DAT_00490950`) as a charge timer, then spawns
  8 projectiles in a ring (types `0x15/0x16`) and plays a burst SFX.

- **Fire Cough** (`DAT_004c2c2c`): uses `player_fire_cough_timer` (`DAT_00490958`) to periodically spawn a
  `0x2d` fire projectile from the muzzle and a small sprite burst.

- **Hot Tempered** (`DAT_004c2bfc`): uses `player_hot_tempered_timer` (`DAT_0049094c`) to periodically spawn a
  ring of projectiles (`0xb` and `9`).

- **Living Fortress** (`DAT_004c2c28`): increments `player_living_fortress_timer` (`DAT_00490954`) while stationary
  (clamped to ~30s); likely consumed by damage scaling elsewhere.

### Weapon spread ("heat") and accuracy recovery

The game models continuous-fire inaccuracy as a per-player "heat" value stored in
`player_spread_heat` (`DAT_00490b68`, offset `0x294`). [static]

- **Decay (recovery):** `player_spread_heat = max(0.01, player_spread_heat - frame_dt * 0.4)`. [static]
  - When Reflex Boost time scaling is active, `frame_dt` is pre-scaled by
    `frame_dt *= time_scale_factor * 1.6666666` before applying the decay. [static]

  - Sharpshooter alters the decay path; the current decompile output has
    conflicting constants (`0.25` and `0.02`), so treat it as **unconfirmed**
    until we validate it at runtime. [static]

- **Gain on fire:** if Sharpshooter is **not** active,
  `player_spread_heat += weapon_table[weapon_id].spread_heat * 1.3`. [static]

  - It is clamped to a maximum of `0.48`. [static]
- **Gain on damage:** when taking damage (and Unstoppable is **not** active),
  `player_spread_heat += damage * 0.01` (also clamped to `0.48`). [static]

- **Shot direction:** when firing, the game jitters the aim point inside a disc,
  then computes the projectile heading from the jittered aim point. [static]

  ```c
  float dx = aim_x - pos_x;
  float dy = aim_y - pos_y;
  float d = sqrtf(dx * dx + dy * dy);

  float max_offset = d * player_spread_heat * 0.5f;
  float dir = (rand() & 0x1ff) * (6.2831853f / 512.0f);
  float mag = (rand() & 0x1ff) * (1.0f / 512.0f); // 0..~0.998

  float ax = aim_x + cosf(dir) * (max_offset * mag);
  float ay = aim_y + sinf(dir) * (max_offset * mag);

  float angle = atan2f(ay - pos_y, ax - pos_x) + 1.5707964f;
  ```

  For pellet weapons, each pellet adds an additional angular jitter:
  `angle += (rand() % 200 - 100) * 0.0015`. [static]

- **Aim indicator:** `ui_render_aim_indicators` draws an aim circle centered at
  `(aim_x, aim_y)` with radius `max(6.0, d * player_spread_heat * 0.5)`. [static]
  This makes the indicator scale with range: the same angular error produces a
  larger circle when aiming farther away.

  - Fill: solid color `rgba(0.0, 0.0, 0.1, 0.3)` via `grim_draw_circle_filled`. [static]
  - Outline: `bulletTrail` texture, UV `(0.5, 0.0)-(0.5, 1.0)`, color alpha `0.55`,
    via `grim_draw_circle_outline`. [static]

  - Grim2D tessellation (grim.dll): fill segments `trunc(r * 0.125 + 12)`, outline
    segments `trunc(r * 0.2 + 14)`, outline outer radius `r + 2.0`. [static]

- **Reload gauge:** `ui_render_aim_indicators` calls
  `ui_draw_clock_gauge_at(&aim_screen_x, 48.0, reload_timer/reload_timer_max)`
  when `progress > 0`. It draws a **32×32** clock gauge at **top-left**
  `(aim_screen_x, aim_screen_y)` using `ui_clockTable` + `ui_clockPointer`.
  Rotation is effectively continuous (ms precision): `ms = trunc(progress * 60000)`, then
  `rotation_rad = (ms/1000) * 0.10471976` (`6°/sec`). `ui_draw_clock_gauge_at`
  ignores the `radius` parameter and hardcodes gauge alpha to `1.0`, and
  `ui_draw_clock_gauge` resets color to
  `(1,1,1,alpha)` (so the preceding orange `grim_set_color(1,0.7,0.1,0.8)` is
  effectively ignored). [static]

- **Cursor render:** `ui_cursor_render` draws a pulsing aim effect using
  `particles_texture` + `effect_select_texture(0x0D)` (64×64 atlas frame) at fixed
  offsets around `ui_mouse_x/y`, then draws `ui_cursor` at `(ui_mouse_x - 2, ui_mouse_y - 2)`
  sized `32×32`. The pulse alpha is
  `alpha = (pow(2.0, sin(t)) + 2.0) * 0.32` with `t += frame_dt * 1.1`. [static]

  - Pulse blend: `SRCBLEND=SRCALPHA` (`0x13=5`), `DESTBLEND=ONE` (`0x14=2`). [static]
  - Cursor blend: `SRCBLEND=SRCALPHA` (`0x13=5`), `DESTBLEND=INVSRCALPHA` (`0x14=6`). [static]

### Reload + spread interactions

- **Sharpshooter** (`DAT_004c2b48`) modifies `player_spread_heat` decay and disables the per-shot heat
  increment (accuracy bloom). [static]

- **Anxious Loader** (`DAT_004c2b90`) reduces the reload timer by `0.05` on each
  primary press while reloading.

- **Stationary Reloader** (`DAT_004c2c10`) triples reload decay when stationary.
- **Angry Reloader** (`DAT_004c2c20`) triggers a projectile ring (`0xb`) when the
  reload timer crosses the 50% mark.

- **Tough Reloader** (`DAT_004c2c30`) halves incoming damage while
  `player_reload_active` (`DAT_00490b78`) is set.

### Regeneration tick (perks_update_effects)

When the Regeneration perk (`DAT_004c2bb0`) is active, `perks_update_effects` slowly
increments player health while in the main loop. This is decoupled from
`player_update` and is skipped in some demo-gated paths.

While Evil Eyes (`DAT_004c2b88`) is active, `perks_update_effects` picks the nearest
creature within `12.0` units of `player_aim_x` and stores the index in
`evil_eyes_target_creature` (`DAT_00490bbc`); `creature_update_all` uses this
index to special-case the target.

### Weapon Power Up cooldown scaling

While `bonus_weapon_power_up_timer > 0` (Weapon Power Up active), `player_update` decays the
shot cooldown (`player_shot_cooldown` / `DAT_00490b84`) at 1.5x speed.

### Bonus overrides

- **Fire Bullets** (bonus id 14): while `player_fire_bullets_timer` (`DAT_00490bcc`) > 0, `projectile_spawn`
  forces player-owned projectiles to type `0x2d` and uses the pellet count from
  the weapon table (`weapon_projectile_pellet_count[weapon_id]`).
  Fire cadence/spread fallback and paired SFX come from:
  `fire_bullets_fallback_shot_cooldown` (`0x004d9040`),
  `fire_bullets_fallback_spread_heat` (`0x004d9048`),
  `fire_bullets_primary_shot_sfx_id` (`0x004d9050`), and
  `fire_bullets_secondary_shot_sfx_id` (`0x004d7fd8`).

- **Spawn guard:** `bonus_spawn_guard` is set while bonus/perk effects spawn
  projectiles to prevent bonus drops from chaining during those effect bursts.

See the data tables for concrete values:

- [Weapon table](../weapon-table.md)
- [Projectile struct](../structs/projectile.md)
- [Effects pools](../structs/effects.md)
- [Perk ID map](../perk-id-map.md)
- [Bonus ID map](../bonus-id-map.md)

## Mode updates

Mode-specific updates are dispatched from the main frame loop:

- Survival: `survival_update` (`FUN_00407cd0`)
- Rush: `rush_mode_update`
- Quests: `quest_mode_update`
- Typ-o-Shooter: separate loop (`typo_gameplay_update_and_render`, `FUN_004457c0`, state `0x12`)

See [Game mode map](../game-mode-map.md) for mode ids.
