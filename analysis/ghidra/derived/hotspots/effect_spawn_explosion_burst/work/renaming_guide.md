# `effect_spawn_explosion_burst` renaming guide

This guide is for `work/0042f6c0_effect_spawn_explosion_burst.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pos_00` -> `burst_pos_ptr`
- `uVar3` -> `rng_value`

## Suggested section comments

- core flash ring setup
- high-detail extra rings branch
- shockwave streak loop (detail-scaled count)

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
