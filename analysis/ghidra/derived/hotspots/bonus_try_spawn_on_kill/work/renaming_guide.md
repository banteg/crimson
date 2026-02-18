# `bonus_try_spawn_on_kill` renaming guide

This guide is for `work/0041f8d0_bonus_try_spawn_on_kill.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pos` -> `kill_pos_ptr`
- `pbVar2` -> `spawned_bonus_ptr`
- `pbVar3` -> `bonus_scan_ptr`
- `uVar4` -> `rng_value`
- `iVar5` -> `effect_scale_rand`
- `iVar1` -> split by role in work copy (`random_roll`, `duplicate_count`, `picked_weapon_id`, `bonus_magnet_count`, `effect_spawn_count`)

## Section Map (Current Work Copy)

- line 24: mode/demo gates that disable kill drops
- line 37: pistol branch with forced-weapon and suppression checks
- line 68: general drop path with bonus-magnet fallback chance
- line 88: duplicate suppression scan and same-weapon rejection
- line 106: accepted-drop burst FX spawn loop

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
