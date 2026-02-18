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
- `fVar1`/`fVar2`/`fVar5` -> split by role in work copy (`dx_to_owner`, `dy_to_owner`, `candidate_x`, `candidate_y`, `delta_y`)

## Section Map (Current Work Copy)

- line 24: alternate-weapon move dampening
- line 35: per-slot overlap test against spawn owners
- line 40: collision rollback plus axis probe retries
- line 64: legacy full-move restore fallback branch

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
