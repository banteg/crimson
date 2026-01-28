# Bonus pickups (rewrite)

This page tracks parity for **world bonus pickups** (the floating pickups you
walk over), comparing the Python + raylib rewrite to the classic exe.

Authoritative reference: `bonus_render` (`0x004295f0`) and `bonus_spawn_at`
(`0x0041f5b0`) in `analysis/ghidra/raw/crimsonland.exe_decompiled.c`.

## What the exe does

### Rendering (`bonus_render`)

For each active `bonus_pool` entry:

- Draw a **32×32 bubble backdrop** using `bonuses.png` frame `0` (grid 4×4).
- Draw the **bonus icon** on top:
  - For most bonuses: `bonuses.png` frame = `bonus_meta.icon_id` (grid 4×4).
  - For **Points** (bonus id `1`): if `amount == 1000`, use `icon_id + 1` (the
    1000‑points icon).
  - For **Weapon** (bonus id `3`): draw a 2×1 sub-rect from `ui_wicons.png`
    based on `weapon_table[weapon_id].hud_icon_id`, scaled to **60×30** at full
    size.
- Animate:
  - Fade in for the first **0.5s** and fade out for the last **0.5s**.
  - Subtle pulse using `sin(...)^4 * 0.25 + 0.75`.
  - Icons (non-weapon) also rotate slightly (`sin(...) * 0.2` radians).

### Effects

- On spawn (`bonus_spawn_at`): spawn a burst of transient effects (`effect_id=0`,
  16 entries).
- On pickup (`bonus_apply`): play `sfx_ui_bonus` and spawn another burst
  (`effect_id=0`, 12 entries, different lifetime/scale defaults). Some bonuses
  also spawn a ring/halo (`effect_id=1`) (e.g. Reflex Boost / Freeze).

## What was missing in the rewrite

- World pickups were drawn as a plain icon (no bubble backdrop).
- No fade/pulse/rotation animation.
- Weapon bonus pickups didn’t render `ui_wicons` (no wide weapon icon).
- No “bonus spawn / bonus pickup” visual burst, and no `sfx_ui_bonus` on pickup.

## What is implemented now

- `src/crimson/game_world.py`: world bonus pickups render with the bubble
  backdrop + animated icon (including weapon `ui_wicons` rendering).
- `src/crimson/effects.py`: `EffectPool.spawn_burst` and `EffectPool.spawn_ring`
  ports used by bonus spawn/pickup effects.
- `src/crimson/creatures/runtime.py`: bonus spawn burst is emitted when a bonus
  drops on creature death.
- `src/crimson/game_world.py`: bonus pickup plays `sfx_ui_bonus` and spawns the
  pickup burst (+ ring for Reflex/Freeze).

## Remaining gaps / TODO

- Bonus label text near players (and Telekinetic “aim to pick up” behavior) from
  the tail of `bonus_render`.
- Full `bonus_apply` FX parity for high-impact bonuses (notably the Nuke
  explosion burst path).
