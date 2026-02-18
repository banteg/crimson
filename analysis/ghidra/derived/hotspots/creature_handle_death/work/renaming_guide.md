# `creature_handle_death` renaming guide

This guide is for `work/0041e910_creature_handle_death.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pos` -> `death_pos_ptr`
- `pcVar1` -> `creature_ptr`
- `uVar6` -> `rng_value`
- `pcVar8` -> `copy_src_ptr`
- `pcVar9` -> `copy_dst_ptr`
- `lVar10` -> `xp_gain_i64`

## Suggested section comments

- kill-history tracking and survival handout gates
- split-on-death cloning branch (`flags & 8`)
- XP grant path (base + double XP timer)
- freeze bonus shatter branch

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
