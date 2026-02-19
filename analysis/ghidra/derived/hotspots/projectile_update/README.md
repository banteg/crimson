# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `27`
- requested targets: `projectile_update`
- resolved targets: `projectile_update`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/projectile_update/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/projectile_update/functions/0041e270_vec2_add.c` (0x0041e270)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0041e400_vec2_add_inplace.c` (0x0041e400)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0041e840_fx_queue_add.c` (0x0041e840)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0041e910_creature_handle_death.c` (0x0041e910)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0041fbb0_fx_spawn_sprite.c` (0x0041fbb0)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00420040_creature_find_nearest.c` (0x00420040)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00420440_projectile_spawn.c` (0x00420440)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00420600_creatures_apply_radius_damage.c` (0x00420600)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/004206a0_creature_find_in_radius.c` (0x004206a0)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00420730_player_find_in_radius.c` (0x00420730)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/004207c0_creature_apply_damage.c` (0x004207c0)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00420b90_projectile_update.c` (0x00420b90)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00427700_fx_queue_add_random.c` (0x00427700)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042eb10_effect_spawn_blood_splatter.c` (0x0042eb10)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042ec80_effect_spawn_freeze_shard.c` (0x0042ec80)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042f080_effect_spawn_shrinkifier_hit.c` (0x0042f080)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042f270_effect_spawn_ion_hit_core.c` (0x0042f270)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042f330_effect_spawn_plasma_hit_core.c` (0x0042f330)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042f3f0_effect_spawn_splitter_hit_burst.c` (0x0042f3f0)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042f540_effect_spawn_ion_hit_sparks.c` (0x0042f540)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042f6c0_effect_spawn_explosion_burst.c` (0x0042f6c0)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0042fcf0_perk_count_get.c` (0x0042fcf0)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0043d260_sfx_play_panned.c` (0x0043d260)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/0043d460_sfx_play_exclusive.c` (0x0043d460)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00452f2a_vec2_normalize_dispatch.c` (0x00452f2a)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00461054___ftol.c` (0x00461054)
- `analysis/ghidra/derived/hotspots/projectile_update/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
