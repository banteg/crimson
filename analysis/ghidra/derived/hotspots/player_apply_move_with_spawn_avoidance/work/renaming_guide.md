# `player_apply_move_with_spawn_avoidance` renaming guide

This guide is for `work/0041e290_player_apply_move_with_spawn_avoidance.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `iVar6` -> `alternate_weapon_perk_count`
- `pcVar3` -> `spawn_owner_ptr`
- `fVar4` -> `collision_radius`
- `pcVar7` -> `spawn_slot_ptr`

## Suggested section comments

- alternate-weapon movement dampening
- per-slot overlap check against spawn owners
- axis-separated rollback fallback when overlap occurs

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
