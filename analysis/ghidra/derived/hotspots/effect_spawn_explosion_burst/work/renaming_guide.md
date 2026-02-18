# `effect_spawn_explosion_burst` renaming guide

This guide is for `work/0042f6c0_effect_spawn_explosion_burst.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pos_00` -> `burst_pos_ptr`
- `uVar3` -> `rng_value`

## Deeper pass notes

- `iVar1` is split in the work copy into `high_detail_ring_index` and `streak_count`.
- `iVar2` is split in the work copy into per-use rolls:
  `ring_rotation_roll`, `streak_angle_roll`, `streak_scale_roll`, `streak_rotation_step_roll`.

## Section Map (Current Work Copy)

- line 24: core explosion flash ring setup and spawn
- line 39: secondary halo overlay setup
- line 48: high-detail delayed outer-ring branch
- line 64: shockwave core pulse setup
- line 94: detail-scaled shockwave streak loop

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
