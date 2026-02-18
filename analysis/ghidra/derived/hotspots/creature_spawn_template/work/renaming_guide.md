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

## Section Map (Current Work Copy)

- line 29: shared root-slot initialization
- line 52: template `0x12` ring boss (root + 8 satellites)
- line 100: template `0x19` escort ring (root + 5 children)
- line 151: entry into the large template dispatch ladder
- line 208: grid/ring + spawner-controller branch family
- line 509: boss-class single entities and controller roots
- line 693: procedural baseline enemy families
- line 718: spawn-slot child templates (`0x31+`)
- line 1132: fixed-stat encounter templates
- line 1315: late-game special templates (`0x3b-0x43`)
- line 1377: apex template `0x00` with internal spawner
- line 1646: template `0x13` linked-chain setup
- line 1709: unknown-template fallback
- line 1714: shared post-dispatch normalization
- line 1731: non-hardcore retry scaling vs hardcore boost path

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
