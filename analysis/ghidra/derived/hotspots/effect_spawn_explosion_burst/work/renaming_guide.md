# `effect_spawn_explosion_burst` renaming guide

This guide is for `work/0042f6c0_effect_spawn_explosion_burst.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pos_00` -> `burst_pos_ptr`
- `uVar3` -> `rng_value`

## Section Map (Current Work Copy)

- line 20: core flash ring setup and first spawn
- line 42: high-detail extra-ring branch
- line 57: shockwave core setup pass
- line 80: detail-scaled shockwave streak loop

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
