---
tags:
  - gameplay
  - perks
  - status-parity
---

# Perks architecture (rewrite)

Perk behavior stays in `perks/impl/`, with its native execution phase visible at
the caller. Metadata, availability and selection stay in `perks/*.py`.

## Execution phases

- **Immediate effects:** `perks/runtime/apply.py` increments the owner's perk
  count, looks up the optional immediate effect in `apply_handlers.py`, then
  mirrors shared perk counts to the other local players. Perk IDs are the keys;
  this map does not impose an execution order.
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

There is no global hook bundle or derived dispatch registry. A perk with behavior
in several phases exports an ordinary function for each phase. The call sites
make each phase's order explicit.

## Context and ownership

`PlayerPerkTickCtx`, `PerkApplyCtx` and `PerksUpdateEffectsCtx` carry the state each
phase uses. The global effect phase requires both creature and terrain FX context:
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
