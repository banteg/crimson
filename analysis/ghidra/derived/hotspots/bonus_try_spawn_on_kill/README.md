# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `5`
- requested targets: `bonus_try_spawn_on_kill`
- resolved targets: `bonus_try_spawn_on_kill`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/bonus_try_spawn_on_kill/work/local_renames.json`
- missing extracted functions: `bonus_spawn_at_pos`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/bonus_try_spawn_on_kill/functions/0041f8d0_bonus_try_spawn_on_kill.c` (0x0041f8d0)
- `analysis/ghidra/derived/hotspots/bonus_try_spawn_on_kill/functions/0042e120_effect_spawn.c` (0x0042e120)
- `analysis/ghidra/derived/hotspots/bonus_try_spawn_on_kill/functions/0042fcf0_perk_count_get.c` (0x0042fcf0)
- `analysis/ghidra/derived/hotspots/bonus_try_spawn_on_kill/functions/00452cd0_weapon_pick_random_available.c` (0x00452cd0)
- `analysis/ghidra/derived/hotspots/bonus_try_spawn_on_kill/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
