# `effect_spawn` renaming guide

This guide is for `work/0042e120_effect_spawn.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

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

## Deeper pass notes

- Work copy splits `pfVar7` into:
  `next_free_effect_ptr` and `template_read_ptr`.
- Work copy replaces repeated `fVar1` reuse with explicit quad/atlas terms:
  `frame_u`, `frame_v`, `uv_step`, `half_height_neg`, `half_height_pos`.

## Section Map (Current Work Copy)

- line 28: detail-preset skip gate
- line 38: free-list pop + template clone
- line 58: size-code UV dispatch shared shape
- line 60: `0x10` atlas lane
- line 83: `0x20` atlas lane
- line 107: `0x80` atlas lane
- line 130: `0x40` atlas lane

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
