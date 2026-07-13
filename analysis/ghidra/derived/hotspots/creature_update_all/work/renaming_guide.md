# `creature_update_all` renaming guide

This guide is for `work/00426220_creature_update_all.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `local_7c` -> `creature_idx`
- `pfVar14` -> `health_ptr`
- `pfVar1` -> `lifecycle_stage_ptr`
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

## Deeper pass notes

- Current work copy already has phase comments and stable pointer locals for the
  AI/movement/death lanes.
- Best next cleanup lead remains splitting `tmp_i32_a`/`tmp_f32_a` by narrower
  AI-mode sub-branches without changing control flow.

## Section Map (Current Work Copy)

- line 46: master creature pool sweep
- line 55: freeze gate for live AI updates
- line 58: flag-driven periodic self/poison damage
- line 81: AI7 pulse timer oscillation (`flags & 0x80`)
- line 106: target-player retarget and auto-target feedback
- line 147: active-body branch main update body
- line 178: AI mode target synthesis ladder
- line 333: heading/movement integration + spawner tick lane
- line 410: animation/cooldown and ranged-attack gates
- line 493: near-contact melee/perk resolution
- line 559: death/corpse shrink/slide branch
- line 614: spawner-class death burst and culling path

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
