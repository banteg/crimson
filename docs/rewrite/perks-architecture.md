---
tags:
  - gameplay
  - perks
  - status-parity
---

# Perks architecture (rewrite)

Immediate perk effects live in one native-shaped function; perks with behavior
in later phases keep it in `perks/impl/`, called from the phase that owns it.
Metadata, availability and selection stay in `perks/*.py`.

## Execution phases

- **Immediate effects:** `perks/runtime/apply.py` is `perk_apply`: it counts the
  perk in the single perk table (`GameplayState.perks`) and runs the perk's
  immediate effect from one `match`, mirroring native's if/else chain.
- **World timing:** `WorldState.world_dt_after_perk_steps` calls
  `apply_reflex_boosted_dt` directly. Session timing applies it once before the
  world step; direct world-step callers use the same method.
- **Per-player updates:** `perks/runtime/player_ticks.py` calls Man Bomb,
  Living Fortress, Fire Cough and Hot Tempered in that order inside `player_update`.
- **Global effects:** `perks/runtime/effects.py` explicitly calls the native
  sequence: player bonus timers, Regeneration, Lean Mean Exp Machine, Death
  Clock, Evil Eyes, Pyrokinetic, then the Jinxed timer and effect.
- **Death effects:** the synchronous `on_player_lethal` callback in
  `sim/world_state.py` calls Final Revenge directly. Creature contact and
  Ammunition Within provide this callback to `player_take_damage`; direct perk
  and projectile health writes bypass it, as in the executable.

There is no global hook bundle or dispatch registry. A perk with behavior in a
later phase exports an ordinary function for that phase, and the call sites make
each phase's order explicit.

## Context and ownership

`PlayerPerkTickCtx` and `PerksUpdateEffectsCtx` carry the state their phases use. The global effect phase requires both creature and terrain FX context:
passing no queue used to skip effects and their RNG draws. Focused tests use real
empty pools and queues when the world is empty. Evil Eyes and Pyrokinetic share a
per-tick aim-target cache through `PerksUpdateEffectsCtx`.

Some perks belong directly to other native paths, such as player damage,
creature damage, projectiles or rendering. Keep those phase boundaries; moving
an effect merely to place it in a registry can change behavior.

## Ordering and validation

Shared timers, health writes and RNG draws make call order observable. Preserve
native guards, float constants and rounding order when editing a perk. Validate
changes with behavioral tests, RNG traces and complete session-state comparisons;
checking that one generated registry mirrors another does not prove behavior.

The import-linter contracts keep implementations and runtime code out of
selection and availability, and prevent selection from importing implementations
directly. Run `just check` after changes.

Use [Perk runtime reference](../re/static/perks-runtime-reference.md) for the
native call-site and implementation map.
