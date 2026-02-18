# `projectile_update` renaming guide

This guide is for `work/00420b90_projectile_update.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## Suggested section comments

- projectile slot iteration and lifetime gates
- collision/hit target resolution
- damage, death, and effect dispatch
- split/spawn child projectile behavior
- perk/bonus interactions and audio cues

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
