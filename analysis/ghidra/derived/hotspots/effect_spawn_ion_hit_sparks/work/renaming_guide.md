# `effect_spawn_ion_hit_sparks` renaming guide

This guide is for `work/0042f540_effect_spawn_ion_hit_sparks.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `fVar1` -> `spark_scale`
- `pvVar2` -> `last_effect_ptr`
- `uVar3` -> `rng_value`
- `iVar4` -> `scale_rand`
- `lVar6` -> `spark_count_i64`

## Deeper pass notes

- Work copy converts pointer countdown `pvVar5` into integer `spark_count`.
- Work copy snapshots `_config_detail_preset` into `detail_preset` before
  applying the low-detail spark halving rule.

## Section Map (Current Work Copy)

- line 22: shared spark template setup from incoming scale
- line 36: spark-count conversion and detail downscale
- line 44: randomized spark spawn loop

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
