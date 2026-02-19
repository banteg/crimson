# `effect_spawn_shrinkifier_hit` renaming guide

This guide is for `work/0042f080_effect_spawn_shrinkifier_hit.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `uVar1` -> `rng_value`
- `iVar2` -> `scale_rand`
- `pvVar3` -> `last_effect_ptr`
- `iVar4` -> `spark_count`

## Deeper pass notes

- Work copy snapshots `_config_detail_preset` into `detail_preset` before
  selecting spark density.

## Section Map (Current Work Copy)

- line 21: core shrinkifier pulse setup (`effect id 1`)
- line 36: follow-up spark template setup (`effect id 0`)
- line 46: detail-dependent spark-count selection
- line 52: randomized spark burst loop (`effect id 0`)

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
