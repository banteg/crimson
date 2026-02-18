# `effect_spawn_splitter_hit_burst` renaming guide

This guide is for `work/0042f3f0_effect_spawn_splitter_hit_burst.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `uVar2` -> `rng_value`
- `iVar3` -> `radius_rand`
- `pvVar4` -> `effect_ptr`
- `lVar7` -> `radius_i64`
- `local_10` -> `spawn_x`
- `local_c` -> `spawn_y`

## Section Map (Current Work Copy)

- line 31: splitter burst template setup
- line 44: random polar sampling loop within radius
- line 55: age/lifetime jitter before each spawn

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
