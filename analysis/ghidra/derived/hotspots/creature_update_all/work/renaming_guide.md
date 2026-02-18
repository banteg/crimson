# `creature_update_all` renaming guide

This guide is for `work/00426220_creature_update_all.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `local_7c` -> `creature_idx`
- `pfVar14` -> `health_ptr`
- `pfVar1` -> `hitbox_size_ptr`
- `puVar2` -> `collision_flag_ptr`
- `pfVar3` -> `attack_cooldown_ptr`
- `piVar4` -> `target_player_ptr`
- `iVar5` -> `spawn_limit`
- `fVar6` -> `target_delta_y`
- `local_78` -> `dist_to_target_player`
- `local_70` -> `move_scale`
- `local_6c` -> `alt_player_dist`
- `local_50` -> `tmp_vec_scratch`

## Medium-confidence temporaries

- `fVar17` -> `tmp_f32_a`
- `fVar15` -> `tmp_f32_b`
- `iVar7` -> `tmp_i32_a`
- `iVar9` -> `tmp_i32_b`
- `uVar8` -> `tmp_u32_a`
- `cVar10` -> `tmp_player_slot`

## Suggested section comments

- tick prologue (`creature_update_tick`, active count, hit flash)
- freeze gate + poison/self-damage flags
- AI7 link timer update (`flags & 0x80`)
- target player selection + auto-target updates
- collision timer and damage branch
- AI mode target synthesis (`ai_mode` switch-like ladder)
- heading/movement integration (`angle_approach`, vel, vec2_add_inplace)
- spawn-slot tick branch (`flags & 4`)
- plaguebearer infection spread
- animation phase advance and wrap
- ranged attack gates (`flags & 0x10`, `flags & 0x100`)
- contact resolution + perk-mediated side effects
- death slide / corpse FX / deactivate

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
