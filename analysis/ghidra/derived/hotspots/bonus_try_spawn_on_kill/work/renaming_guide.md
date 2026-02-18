# `bonus_try_spawn_on_kill` renaming guide

This guide is for `work/0041f8d0_bonus_try_spawn_on_kill.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pos` -> `kill_pos_ptr`
- `pbVar2` -> `spawned_bonus_ptr`
- `pbVar3` -> `bonus_scan_ptr`
- `uVar4` -> `rng_value`
- `iVar5` -> `effect_scale_rand`

## Suggested section comments

- mode and demo gates (skip bonus drops)
- forced weapon drop branch when pistol-only
- duplicate/drop suppression (`bonus_pool` scan)
- spawn FX burst for accepted drops

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
