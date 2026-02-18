# `player_take_damage` renaming guide

This guide is for `work/00425e50_player_take_damage.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

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

## Suggested section comments

- pre-hit perk gates (`death_clock`, `tough_reloader`)
- dodge branch (`ninja` / `dodger`)
- lethal branch + final revenge AoE retaliation
- post-hit spread/heading penalties

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
