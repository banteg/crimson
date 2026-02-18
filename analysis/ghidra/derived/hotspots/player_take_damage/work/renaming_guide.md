# `player_take_damage` renaming guide

This guide is for `work/00425e50_player_take_damage.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pos` -> `player_pos_ptr`
- `bVar3` -> `dodge_triggered`
- `uVar5` -> `rng_value`
- `pcVar6` -> `creature_ptr`
- `bVar7` -> `was_dead_before_hit`
- `local_c` -> `damage_scale`
- `local_8` -> `zero_impulse`

## Deeper pass notes

- `iVar4` is split in the work copy by role:
  `perk_count`, `rand_roll`, `creature_idx`.
- `fVar1`/`fVar2` are split into clearer lanes:
  `blast_delta_x`, `blast_delta_y`, `blast_falloff`, `next_spread_heat`.

## Section Map (Current Work Copy)

- line 29: hard pre-gates (`death_clock`, `tough_reloader`)
- line 40: shield short-circuit path
- line 50: dodge evaluation (`ninja` / `dodger`)
- line 67: damage apply vs highlander roulette
- line 80: alive vs lethal branch + final revenge resolution
- line 128: post-hit heading/spread penalties and low-health pulse trigger

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
