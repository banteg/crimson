# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `6`
- requested targets: `creature_spawn_template`
- resolved targets: `creature_spawn_template`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/creature_spawn_template/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/creature_spawn_template/functions/00401870_console_printf.c` (0x00401870)
- `analysis/ghidra/derived/hotspots/creature_spawn_template/functions/00428140_creature_alloc_slot.c` (0x00428140)
- `analysis/ghidra/derived/hotspots/creature_spawn_template/functions/0042ef60_effect_spawn_burst.c` (0x0042ef60)
- `analysis/ghidra/derived/hotspots/creature_spawn_template/functions/00430ad0_creature_spawn_slot_alloc.c` (0x00430ad0)
- `analysis/ghidra/derived/hotspots/creature_spawn_template/functions/00430af0_creature_spawn_template.c` (0x00430af0)
- `analysis/ghidra/derived/hotspots/creature_spawn_template/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
