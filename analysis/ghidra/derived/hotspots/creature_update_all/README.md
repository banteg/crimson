# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `18`
- requested targets: `creature_update_all`
- resolved targets: `creature_update_all`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/creature_update_all/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/creature_update_all/functions/0041e400_vec2_add_inplace.c` (0x0041e400)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/0041e910_creature_handle_death.c` (0x0041e910)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/0041f430_angle_approach.c` (0x0041f430)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00420440_projectile_spawn.c` (0x00420440)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/004207c0_creature_apply_damage.c` (0x004207c0)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00425d80_plaguebearer_spread_infection.c` (0x00425d80)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00425e50_player_take_damage.c` (0x00425e50)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00426220_creature_update_all.c` (0x00426220)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00427700_fx_queue_add_random.c` (0x00427700)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00427840_fx_queue_add_rotated.c` (0x00427840)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/0042eb10_effect_spawn_blood_splatter.c` (0x0042eb10)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/0042ef60_effect_spawn_burst.c` (0x0042ef60)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/0042fcf0_perk_count_get.c` (0x0042fcf0)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00430af0_creature_spawn_template.c` (0x00430af0)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/0043d260_sfx_play_panned.c` (0x0043d260)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00452f2a_vec2_normalize_dispatch.c` (0x00452f2a)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00461054___ftol.c` (0x00461054)
- `analysis/ghidra/derived/hotspots/creature_update_all/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
