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
- `uVar2`/`uVar3`/`uVar4` -> `copy_pad_byte0`/`copy_pad_byte1`/`copy_pad_byte2`
- `iVar5`/`iVar7` -> split by role in work copy (`split_clone_id`, `copy_word_count`, `perk_id_bloody_mess`, `freeze_spawn_count`, `freeze_angle_roll`)

## Section Map (Current Work Copy)

- line 29: forced bonus drop branch (`flags & 0x400`)
- line 35: survival kill-history and handout gate bookkeeping
- line 50: spawn-slot unlink for slot-owned creatures (`flags & 4`)
- line 55: split-on-death clone branches (`flags & 8`, size gate)
- line 110: corpse keep-vs-clear policy
- line 118: XP add path (base and double-XP timer)
- line 141: freeze shard/shatter cleanup branch

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
