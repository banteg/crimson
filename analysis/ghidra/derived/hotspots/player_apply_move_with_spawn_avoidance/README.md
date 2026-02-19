# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `2`
- requested targets: `player_apply_move_with_spawn_avoidance`
- resolved targets: `player_apply_move_with_spawn_avoidance`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/player_apply_move_with_spawn_avoidance/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/player_apply_move_with_spawn_avoidance/functions/0041e290_player_apply_move_with_spawn_avoidance.c` (0x0041e290)
- `analysis/ghidra/derived/hotspots/player_apply_move_with_spawn_avoidance/functions/0042fcf0_perk_count_get.c` (0x0042fcf0)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
