# `creature_spawn_template` renaming guide

This guide is for `work/00430af0_creature_spawn_template.work.c`.
Use it as a consistent naming scheme while preserving branch labels.

## Scripted renames

- `work/local_renames.json` is applied by `scripts/extract_decompile_functions.py` on each rerun.
- Update that JSON, then rerun extraction to apply renames consistently.

## High-confidence locals

- `pfVar5` -> `origin_pos_ptr`
- `iVar6` -> `root_slot_idx`
- `iVar8` -> `child_slot_idx`
- `uVar9` -> `rng_value`
- `pcVar10` -> `creature_ptr`

## Deeper pass notes

- Work copy names heading random rolls as `random_heading_roll`.
- Work copy replaces pointer-as-counter loops in templates `0x12` and `0x19`
  with explicit `ring_member_idx`.

## Section Map (Current Work Copy)

- line 31: shared root-slot initialization
- line 54: template `0x12` ring boss (root + 8 satellites)
- line 102: template `0x19` escort ring (root + 5 children)
- line 153: entry into the large template dispatch ladder
- line 210: grid/ring + spawner-controller branch family
- line 511: boss-class single entities and controller roots
- line 695: procedural baseline enemy families
- line 720: spawn-slot child templates (`0x31+`)
- line 1134: fixed-stat encounter templates
- line 1317: late-game special templates (`0x3b-0x43`)
- line 1379: apex template `0x00` with internal spawner
- line 1648: template `0x13` linked-chain setup
- line 1711: unknown-template fallback
- line 1716: shared post-dispatch normalization
- line 1733: non-hardcore retry scaling vs hardcore boost path

## Notes

- Keep `LAB_...` labels unchanged for traceability with differential logs.
- Keep float literals untouched in parity-critical branches unless capture evidence says otherwise.
- Avoid deleting unknown branches; mark with `TODO(parity)` and move on.
