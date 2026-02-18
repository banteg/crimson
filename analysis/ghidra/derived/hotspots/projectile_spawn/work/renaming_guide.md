# `projectile_spawn` renaming guide

This guide is for `work/00420440_projectile_spawn.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `ppVar1` -> `projectile_slot_ptr`
- `iVar2` -> `projectile_slot_idx`
- `fVar3` -> split by role in work copy (`cos_component`, `sin_component`)

## Section Map (Current Work Copy)

- line 21: owner-class Fire Bullets override gate
- line 30: free-slot scan with slot `0x5f` fallback
- line 40: shared spawn initialization and initial velocity setup
- line 68: hit-radius branch (ion/plasma heavy radius vs default radius)
- line 74: special damage-pool overrides (`gauss`, `fire_bullets`, `blade`)

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
