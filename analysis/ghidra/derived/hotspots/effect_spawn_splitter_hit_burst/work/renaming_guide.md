# `effect_spawn_splitter_hit_burst` renaming guide

This guide is for `work/0042f3f0_effect_spawn_splitter_hit_burst.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `fVar1` -> `angle_radians`
- `uVar2` -> `rng_value`
- `iVar3` -> `radius_rand`
- `pvVar4` -> `last_effect_ptr`
- `lVar7` -> `radius_i64`
- `local_10` -> `spawn_x`
- `local_c` -> `spawn_y`

## Deeper pass notes

- Work copy splits `fVar6` trig reuse into `cos_component` and `sin_component`.
- Work copy names template carry-over stack slots as
  `legacy_color_seed_b` and `legacy_color_seed_a`.

## Section Map (Current Work Copy)

- line 28: legacy stack seed carry-over
- line 33: splitter burst template setup
- line 45: random polar sampling loop within radius
- line 57: age/lifetime jitter before each spawn

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
