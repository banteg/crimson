---
tags:
  - gameplay
  - perks
  - status-parity
---

# Perks architecture (rewrite)

This document is the canonical architecture contract for perk runtime behavior in
the Python rewrite.

Goals:

- **Original fidelity**: keep hook order and side effects aligned with native flow.
- **Navigability**: “open a perk file, see that perk’s runtime logic.”
- **Deterministic auditability**: stable RNG consumption and dispatch order for
  differential testing.

## Design overview

Perk runtime logic is split into two layers:

1. **Per-perk ownership modules** in `src/crimson/perks/*.py`
   - Each perk that has runtime behavior exports exactly one `HOOKS` value:
     `PerkHooks(...)`.
   - The same file contains the perk’s hook functions.
2. **One canonical manifest** in `src/crimson/perks/manifest.py`
   - `PERK_HOOKS_IN_ORDER`: parity-critical master ordering.
   - Derived dispatch tables used by runtime call sites.

There are no compatibility registry wrappers/re-exports for perk runtime
dispatch. If you need runtime ownership or hook order, use `manifest.py`.

## Runtime surfaces

Hook shape is defined in `src/crimson/perks/hook_types.py`:

- `apply_handler`: immediate on-pick logic (`perk_apply` path)
- `world_dt_step`: frame-dt transforms (e.g. Reflex Boosted)
- `player_tick_steps`: per-player tick hooks inside `player_update`
- `effects_steps`: global per-frame perk effects (`perks_update_effects`)
- `player_death_hook`: death-triggered behavior (e.g. Final Revenge)

`PerkHooks` fields are optional; each perk declares only what it owns.

Example:

```python
HOOKS = PerkHooks(
    perk_id=PerkId.INSTANT_WINNER,
    apply_handler=apply_instant_winner,
)
```

## Dispatch integration points

### 1) Apply-time perks

- Entry: `src/crimson/perks/apply.py:perk_apply`
- Source: `PERK_APPLY_HANDLERS` derived from `PERK_HOOKS_IN_ORDER`
- Flow:
  1. Increment owner perk count (`adjust_perk_count`).
  2. Run apply handler if registered.
  3. Mirror `perk_counts` from player 0 to other players.

This keeps multiplayer perk-count state deterministic and aligned with native
shared-count behavior.

### 2) World dt hooks

- Entry: `src/crimson/sim/world_state.py:WorldState.step`
- Source: `WORLD_DT_STEPS`
- Runs first, before core simulation work.

### 3) Perk effects hooks

- Entry: `src/crimson/perks/effects.py:perks_update_effects`
- Source: `PERKS_UPDATE_EFFECT_STEPS`
- Called early in `WorldState.step`, after aim staging and before
  `state.effects.update(...)`.
- `update_player_bonus_timers` is always first in this sequence.

### 4) Player tick hooks

- Entry: `src/crimson/gameplay.py:player_update` via
  `src/crimson/perks/player_ticks.py:apply_player_perk_ticks`
- Source: `PLAYER_PERK_TICK_STEPS`
- Runs once per player each tick.

### 5) Player death hooks

- Entry: `src/crimson/sim/world_state.py:WorldState.step`
- Source: `PLAYER_DEATH_HOOKS`
- Runs for players transitioning alive -> dead during the current step.

## Ordering and RNG invariants

These rules are parity-critical:

1. `PERK_HOOKS_IN_ORDER` is authoritative for hook dispatch order.
2. Derived registries preserve this order and must not sort/reorder.
3. Adding/removing/reordering hooks can change RNG draw order and differential
   trace behavior, even when gameplay looks similar.
4. Keep perk-side RNG draws inside the perk’s own hook file unless ordering
   evidence requires otherwise.
5. Avoid moving logic between phases (`apply_handler` vs `effects_steps` vs
   `player_tick_steps`) without native evidence.

## Anti-drift guardrails

Guard tests live in `tests/test_feature_hook_registries.py`:

- Explicit expected world-dt and death-hook wiring.
- Single runtime owner per perk (`PERK_HOOKS_IN_ORDER` has unique `perk_id`).
- Derived registries are exact projections of manifest entries.
- Effects step prefix invariant (`update_player_bonus_timers` first).

Validation command:

- `just check`

## Contributor workflow for perk changes

When adding or refactoring a perk runtime hook:

1. Implement/update the hook function in that perk’s module.
2. Update that module’s `HOOKS = PerkHooks(...)`.
3. Add/update the import + placement in `PERK_HOOKS_IN_ORDER` in
   `src/crimson/perks/manifest.py`.
4. Keep deterministic behavior explicit:
   - do not normalize parity-sensitive float constants.
   - preserve native guard/branch structure when it affects RNG or timing.
5. Add/update tests:
   - scenario tests for the perk behavior.
   - registry invariant tests if hook shape/order changed.
6. Run `just check`.

## What this architecture intentionally does not do

- It does not try to force all perk behavior through one hook type. Some perks
  are owned by other hot paths by design (`player_take_damage`,
  `creature_apply_damage`, projectile systems, rendering paths).
- It does not hide phase boundaries. The phase where a perk runs is part of the
  parity contract.

Use [perk matrix](perk-matrix.md) with this page:

- `perk-matrix.md` answers “where does this perk run?”
- this page answers “how does perk runtime registration and dispatch work?”
