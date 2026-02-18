# `effect_spawn` renaming guide

This guide is for `work/0042e120_effect_spawn.work.c`.
Use it as a consistent first-pass naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `uVar4` -> `detail_skip_bit`
- `iVar2` -> `size_code`
- `iVar3` -> `frame_idx`
- `pfVar5` -> `effect_ptr`
- `iVar6` -> `copy_word_idx`
- `pfVar8` -> `effect_write_ptr`

## Suggested section comments

- detail-preset skip gate
- free-list pop and template copy
- UV/layout setup by size-code bucket (`0x10/0x20/0x40/0x80`)

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
