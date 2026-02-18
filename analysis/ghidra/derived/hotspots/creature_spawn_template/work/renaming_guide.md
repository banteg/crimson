# `creature_spawn_template` renaming guide

This guide is for `work/00430af0_creature_spawn_template.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pfVar5` -> `origin_pos_ptr`
- `iVar6` -> `root_slot_idx`
- `iVar8` -> `child_slot_idx`
- `uVar9` -> `rng_value`
- `pcVar10` -> `creature_ptr`

## Suggested section comments

- root creature init shared by all templates
- template-specific companion spawn patterns (rings, chains, grids)
- reward/health/size tables by template id

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
