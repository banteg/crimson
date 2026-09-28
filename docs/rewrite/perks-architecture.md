---
tags:
  - gameplay
  - perks
  - status-parity
---

# Perks architecture (rewrite)

Perk behavior lives inside the native functions that own it, in native order.
Metadata, availability and selection stay in `perks/*.py`.

## Execution phases

- **Immediate effects:** `perks/apply.py` is `perk_apply`: it counts the
  perk in the single perk table (`GameplayState.perks`) and runs the perk's
  immediate effect from one `match`, mirroring native's if/else chain.
- **World timing:** `WorldState.world_dt_after_perk_steps` applies Reflex
  Boosted's 0.9 frame_dt scale, as native `game_frame_update` does.
- **Per-player updates:** `_player_tick_perks` in `gameplay.py` runs Man Bomb,
  Living Fortress, Fire Cough and Hot Tempered in that order inside `player_update`.
- **Global effects:** `perks/effects.py` is `perks_update_effects`: Regeneration,
  Lean Mean Exp Machine, the per-player Death Clock and bonus timers, one
  creature search at the aim for Doctor, Pyrokinetic and Evil Eyes, then Jinxed.
- **Death effects:** `player_take_damage` runs the Final Revenge blast inline.
  Direct perk and projectile health writes bypass it, as in the executable.

Native targets player one in several of these; without `preserve_bugs` the
rewrite gives every live player the same treatment.

Some perks belong directly to other native paths, such as creature damage,
projectiles or rendering. Keep those phase boundaries; moving an effect out of its
native function can change behavior.

## Ordering and validation

Shared timers, health writes and RNG draws make call order observable. Preserve
native guards, float constants and rounding order when editing a perk. Validate
changes with behavioral tests, RNG traces and complete session-state comparisons;
checking that one generated registry mirrors another does not prove behavior.
Run `just check` after changes.

Use [Perk runtime reference](../re/static/perks-runtime-reference.md) for the
native call-site and implementation map.
