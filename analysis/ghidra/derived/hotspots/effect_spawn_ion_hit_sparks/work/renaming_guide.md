# `effect_spawn_ion_hit_sparks` renaming guide

This guide is for `work/0042f540_effect_spawn_ion_hit_sparks.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `fVar1` -> `spark_scale`
- `pvVar2` -> `effect_ptr`
- `uVar3` -> `rng_value`
- `iVar4` -> `scale_rand`
- `pvVar5` -> `sparks_left`
- `lVar6` -> `spark_count_i64`

## Section Map (Current Work Copy)

- line 21: lifetime/size setup from incoming scale
- line 34: spark-count conversion and detail downscale
- line 41: randomized spark spawn loop

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
