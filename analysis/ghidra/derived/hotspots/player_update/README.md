# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `22`
- requested targets: `player_update`
- resolved targets: `player_update`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/player_update/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/player_update/functions/00413430_player_start_reload.c` (0x00413430)
- `analysis/ghidra/derived/hotspots/player_update/functions/00413540_player_heading_approach_target.c` (0x00413540)
- `analysis/ghidra/derived/hotspots/player_update/functions/004136b0_player_update.c` (0x004136b0)
- `analysis/ghidra/derived/hotspots/player_update/functions/00417640_vec2_sub.c` (0x00417640)
- `analysis/ghidra/derived/hotspots/player_update/functions/00417660_vec2_length.c` (0x00417660)
- `analysis/ghidra/derived/hotspots/player_update/functions/0041e290_player_apply_move_with_spawn_avoidance.c` (0x0041e290)
- `analysis/ghidra/derived/hotspots/player_update/functions/0041e8d0_input_aim_pov_left_active.c` (0x0041e8d0)
- `analysis/ghidra/derived/hotspots/player_update/functions/0041e8f0_input_aim_pov_right_active.c` (0x0041e8f0)
- `analysis/ghidra/derived/hotspots/player_update/functions/0041fbb0_fx_spawn_sprite.c` (0x0041fbb0)
- `analysis/ghidra/derived/hotspots/player_update/functions/00420130_fx_spawn_particle.c` (0x00420130)
- `analysis/ghidra/derived/hotspots/player_update/functions/00420240_fx_spawn_particle_slow.c` (0x00420240)
- `analysis/ghidra/derived/hotspots/player_update/functions/00420360_fx_spawn_secondary_projectile.c` (0x00420360)
- `analysis/ghidra/derived/hotspots/player_update/functions/00420440_projectile_spawn.c` (0x00420440)
- `analysis/ghidra/derived/hotspots/player_update/functions/00425e50_player_take_damage.c` (0x00425e50)
- `analysis/ghidra/derived/hotspots/player_update/functions/0042e120_effect_spawn.c` (0x0042e120)
- `analysis/ghidra/derived/hotspots/player_update/functions/0042eb10_effect_spawn_blood_splatter.c` (0x0042eb10)
- `analysis/ghidra/derived/hotspots/player_update/functions/0042fcf0_perk_count_get.c` (0x0042fcf0)
- `analysis/ghidra/derived/hotspots/player_update/functions/0043d260_sfx_play_panned.c` (0x0043d260)
- `analysis/ghidra/derived/hotspots/player_update/functions/00446030_input_primary_just_pressed.c` (0x00446030)
- `analysis/ghidra/derived/hotspots/player_update/functions/00452f2a_vec2_normalize_dispatch.c` (0x00452f2a)
- `analysis/ghidra/derived/hotspots/player_update/functions/00461054___ftol.c` (0x00461054)
- `analysis/ghidra/derived/hotspots/player_update/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
