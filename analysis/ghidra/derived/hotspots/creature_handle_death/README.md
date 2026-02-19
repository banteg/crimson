# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `9`
- requested targets: `creature_handle_death`
- resolved targets: `creature_handle_death`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/creature_handle_death/work/local_renames.json`
- missing extracted functions: `bonus_spawn_at`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/0041e910_creature_handle_death.c` (0x0041e910)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/0041f8d0_bonus_try_spawn_on_kill.c` (0x0041f8d0)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/00427700_fx_queue_add_random.c` (0x00427700)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/00428140_creature_alloc_slot.c` (0x00428140)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/0042ec80_effect_spawn_freeze_shard.c` (0x0042ec80)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/0042ee00_effect_spawn_freeze_shatter.c` (0x0042ee00)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/0042ef60_effect_spawn_burst.c` (0x0042ef60)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/00461054___ftol.c` (0x00461054)
- `analysis/ghidra/derived/hotspots/creature_handle_death/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
