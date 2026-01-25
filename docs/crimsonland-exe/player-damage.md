---
tags:
  - status-analysis
---

# Player damage contract (player_take_damage)

This page documents the damage intake behavior for a player in the classic game
(`crimsonland.exe` v1.9.93), centered on `player_take_damage` (`0x00425e50`).

**Source of truth:** decompiles (Ghidra/IDA/Binary Ninja). Code under `src/` is our
reimplementation and can drift.

See also:

- `docs/structs/player.md` (player struct offsets used below)
- `docs/creatures/update.md` (where contact damage is applied from `creature_update_all`)
- `docs/crimsonland-exe/frame-loop.md` (game-over transition logic)

## Inputs and side effects

Inputs:

- `player_index` (0/1)
- `damage` (float)

Global side effects:

- Sets `survival_reward_damage_seen = 1` (used by `survival_update` handout gating).

## Core gates (must-have)

### 1) Death Clock immunity

If the **Death Clock** perk is active, `player_take_damage` returns immediately and ignores damage.

### 2) Tough Reloader mitigation

If the **Tough Reloader** perk is active and the player is currently reloading
(`player_reload_active` at offset `0x2a4`), incoming damage is halved:

- `damage *= 0.5`

### 3) Shield immunity

If `player_shield_timer` (offset `0x2f4`) is positive, `player_take_damage` returns immediately
and the hit is ignored.

## Applying damage

When not gated above, the function computes an effective damage scale and subtracts from
`player_health` (offset `0x00`):

- Base scale is `1.0`.
- **Thick Skinned** (perk) scales damage by `~0.666`.
- **Ninja** / **Dodger** (perks) can “dodge” the hit (random chance); a dodged hit skips all
  post-hit effects.

## Death timer behavior

When a hit reduces `player_health` below `0`, `player_take_damage` updates the player’s death timer
stored at `player_health - 0x14` (`player_death_timer` in `docs/structs/player.md`):

- `player_death_timer -= frame_dt * 28.0`

Other gameplay code continues to use this timer to drive the game-over transition once all players
are dead; see `docs/crimsonland-exe/frame-loop.md`.

## Low-health warnings

When the post-hit `player_health` is `<= 20`, `player_take_damage` occasionally resets
`player_low_health_timer` (offset `0x2ec`) to `0` when `(rand() & 7) == 3` (1/8 chance per hit).

The exact meaning of the timer is covered in `docs/structs/player.md` (it gates warning effects/SFX).

## Contact damage frequency gate (from creatures)

Contact damage is not applied every frame: `creature_update_all` uses a per-creature contact timer
to throttle calls into `player_take_damage`.

Contract (per creature; see `docs/creatures/struct.md`):

- `creature_collision_flag` (byte, offset `0x09`) enables the contact-damage timer.
- While the flag is set, `creature_collision_timer` (float, offset `0x0c`) decrements by `dt`.
- When the timer drops below zero, native logic:
  - adds `0.5` seconds to the timer (no loop), and
  - calls `player_take_damage(creature_target_player, creature_contact_damage)`.

This yields an effective upper bound of ~2 contact-damage ticks per second per colliding creature.

