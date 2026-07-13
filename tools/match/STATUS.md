# Matching Status

Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.

**23/2161** functions matched, **1079/675651** code bytes (**0.2%**). Byte totals are manifest function extents with terminal padding trimmed.

## Images

| image | functions | bytes | code | scratches |
|---|---:|---:|---:|---:|
| crimsonland.exe | 16/986 | 965/385754 | 0.3% | 16/29 |
| grim.dll | 7/1175 | 114/289897 | 0.0% | 7/7 |

## crimsonland.exe

**16/986** functions, **965/385754** bytes (**0.3%**), **16/29** scratches verified.

| state | function | address | bytes | insns | match | prefix | refs ok/?/! | build | note |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| match | console_input_clear | 0x00401030 | 18 | 5/5 | 100.00% | 5/5 | 3/0/0 |  | smoke |
| match | console_input_buffer | 0x00401050 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | console_cmd_argc_get | 0x00401150 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| wip | bonus_apply | 0x00409890 | 2693 | 664/668 | 65.32% | 27/668 | 161/0/14 |  | gameplay-bonus-switch |
| match | player_start_reload | 0x00413430 | 263 | 67/67 | 100.00% | 67/67 | 28/0/0 |  | gameplay-reload |
| wip | player_heading_approach_target | 0x00413540 | 354 | 93/95 | 59.57% | 5/95 | 12/0/0 |  | gameplay-angle-x87 |
| match | vec2_length | 0x00417660 | 26 | 12/12 | 100.00% | 12/12 | 0/0/0 |  | x87-fsqrt |
| match | game_sequence_get | 0x0041df60 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| wip | player_apply_move_with_spawn_avoidance | 0x0041e290 | 356 | 135/131 | 66.17% | 1/131 | 7/0/1 |  | gameplay-movement |
| match | bonus_alloc_slot | 0x0041f580 | 46 | 14/14 | 100.00% | 14/14 | 4/0/0 |  | gameplay-bonus-pool |
| match | weapon_table_entry | 0x0041fc60 | 19 | 6/6 | 100.00% | 6/6 | 1/0/0 |  | gameplay-weapon-table |
| wip | creature_find_nearest | 0x00420040 | 225 | 91/89 | 72.22% | 7/89 | 3/0/1 |  | gameplay-target-search |
| wip | fx_spawn_secondary_projectile | 0x00420360 | 218 | 67/65 | 80.30% | 0/65 | 13/0/0 |  | gameplay-secondary-projectile |
| wip | projectile_spawn | 0x00420440 | 400 | 118/126 | 67.21% | 0/126 | 11/0/0 |  | gameplay-projectile |
| match | projectile_reset_pools | 0x004205d0 | 37 | 11/11 | 100.00% | 11/11 | 4/0/0 |  | gameplay-pool-reset |
| wip | creatures_apply_radius_damage | 0x00420600 | 159 | 58/57 | 74.78% | 11/57 | 4/0/1 |  | gameplay-radius-damage |
| wip | creature_find_in_radius | 0x004206a0 | 133 | 51/47 | 40.82% | 0/47 | 3/0/1 |  | gameplay-target-search |
| wip | player_find_in_radius | 0x00420730 | 133 | 54/54 | 64.81% | 9/54 | 4/0/1 |  | gameplay-target-search |
| wip | player_take_damage | 0x00425e50 | 969 | 266/267 | 77.67% | 9/267 | 62/0/2 |  | gameplay-player-damage |
| wip | creature_reset_all | 0x004281e0 | 46 | 13/13 | 92.31% | 2/13 | 3/0/0 |  | gameplay-creature-reset |
| match | creatures_none_active | 0x00428210 | 40 | 12/12 | 100.00% | 12/12 | 4/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-creature-scan |
| wip | creature_spawn | 0x00428240 | 334 | 78/79 | 77.71% | 7/79 | 21/0/5 |  | gameplay-creature-spawn |
| match | bonus_label_for_entry | 0x00429580 | 99 | 30/30 | 100.00% | 30/30 | 11/0/0 |  | gameplay-bonus-label |
| match | perk_select_random | 0x0042fbd0 | 89 | 32/32 | 100.00% | 32/32 | 8/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-perk-rng |
| match | perk_count_get | 0x0042fcf0 | 12 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | gameplay-perk-count |
| match | creature_spawn_slot_alloc | 0x00430ad0 | 30 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-spawn-slots |
| wip | creature_spawn_template | 0x00430af0 | 14099 | 2722/3159 | 58.09% | 23/3159 | 306/4/1 |  | gameplay-spawn-switch |
| match | weapon_pick_random_available | 0x00452cd0 | 107 | 36/36 | 100.00% | 36/36 | 8/0/0 |  | gameplay-weapon-rng |
| match | weapon_refresh_available | 0x00452e40 | 161 | 48/48 | 100.00% | 48/48 | 17/0/0 |  | gameplay-weapon-unlocks |

## grim.dll

**7/1175** functions, **114/289897** bytes (**0.0%**), **7/7** scratches verified.

| state | function | address | bytes | insns | match | prefix | refs ok/?/! | build | note |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| match | grim_noop | 0x10001160 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | smoke |
| match | grim_get_error_text | 0x10006ca0 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_get_time_ms | 0x10006e40 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_get_frame_dt | 0x10006e60 | 33 | 9/9 | 100.00% | 9/9 | 4/0/0 |  | branch-x87 |
| match | grim_is_mouse_button_down | 0x10007410 | 38 | 11/11 | 100.00% | 11/11 | 3/0/0 |  | branch-call-stdcall |
| match | grim_get_mouse_x | 0x10007510 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_get_mouse_wheel_delta | 0x10007560 | 23 | 7/7 | 100.00% | 7/7 | 3/0/0 |  | branch-x87 |
