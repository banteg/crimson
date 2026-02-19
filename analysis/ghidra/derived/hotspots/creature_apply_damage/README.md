# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `6`
- requested targets: `creature_apply_damage`
- resolved targets: `creature_apply_damage`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/creature_apply_damage/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/creature_apply_damage/functions/0041e910_creature_handle_death.c` (0x0041e910)
- `analysis/ghidra/derived/hotspots/creature_apply_damage/functions/004207c0_creature_apply_damage.c` (0x004207c0)
- `analysis/ghidra/derived/hotspots/creature_apply_damage/functions/0042e120_effect_spawn.c` (0x0042e120)
- `analysis/ghidra/derived/hotspots/creature_apply_damage/functions/0042fcf0_perk_count_get.c` (0x0042fcf0)
- `analysis/ghidra/derived/hotspots/creature_apply_damage/functions/0043d260_sfx_play_panned.c` (0x0043d260)
- `analysis/ghidra/derived/hotspots/creature_apply_damage/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
