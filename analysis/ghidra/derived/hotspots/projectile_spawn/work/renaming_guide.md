# `projectile_spawn` renaming guide

This guide is for `work/00420440_projectile_spawn.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `ppVar1` -> `slot_ptr`
- `iVar2` -> `slot_idx`

## Suggested section comments

- owner-id scoreboard gate + Fire Bullets override
- free-slot scan and fallback policy
- type-specific hit-radius / damage-pool init

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
