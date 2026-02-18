# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `6`
- requested targets: `player_take_damage`
- resolved targets: `player_take_damage`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/player_take_damage/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/player_take_damage/functions/004207c0_creature_apply_damage.c` (0x004207c0)
- `analysis/ghidra/derived/hotspots/player_take_damage/functions/00425e50_player_take_damage.c` (0x00425e50)
- `analysis/ghidra/derived/hotspots/player_take_damage/functions/0042f6c0_effect_spawn_explosion_burst.c` (0x0042f6c0)
- `analysis/ghidra/derived/hotspots/player_take_damage/functions/0042fcf0_perk_count_get.c` (0x0042fcf0)
- `analysis/ghidra/derived/hotspots/player_take_damage/functions/0043d260_sfx_play_panned.c` (0x0043d260)
- `analysis/ghidra/derived/hotspots/player_take_damage/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
