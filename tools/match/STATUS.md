# Matching Status

Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.

**19/2161** functions matched, **459/675651** code bytes (**0.1%**). Byte totals are manifest function extents with terminal padding trimmed.

## Images

| image | functions | bytes | code | scratches |
|---|---:|---:|---:|---:|
| crimsonland.exe | 12/986 | 345/385754 | 0.1% | 12/24 |
| grim.dll | 7/1175 | 114/289897 | 0.0% | 7/7 |

## crimsonland.exe

**12/986** functions, **345/385754** bytes (**0.1%**), **12/24** scratches at 100%.

| state | function | address | bytes | insns | match | prefix | build | note |
|---|---|---|---:|---:|---:|---:|---|---|
| match | console_input_clear | 0x00401030 | 18 | 5/5 | 100.00% | 5/5 |  | smoke |
| match | console_input_buffer | 0x00401050 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | console_cmd_argc_get | 0x00401150 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| wip | bonus_apply | 0x00409890 | 2693 | 661/668 | 64.41% | 6/668 |  | gameplay-bonus-switch |
| wip | player_start_reload | 0x00413430 | 263 | 67/67 | 94.03% | 29/67 |  | gameplay-reload |
| wip | player_heading_approach_target | 0x00413540 | 354 | 96/95 | 28.27% | 2/95 |  | gameplay-angle-x87 |
| match | vec2_length | 0x00417660 | 26 | 12/12 | 100.00% | 12/12 |  | x87-fsqrt |
| match | game_sequence_get | 0x0041df60 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| wip | player_apply_move_with_spawn_avoidance | 0x0041e290 | 356 | 135/131 | 64.66% | 1/131 |  | gameplay-movement |
| match | bonus_alloc_slot | 0x0041f580 | 46 | 14/14 | 100.00% | 14/14 |  | gameplay-bonus-pool |
| match | weapon_table_entry | 0x0041fc60 | 19 | 6/6 | 100.00% | 6/6 |  | gameplay-weapon-table |
| wip | creature_find_nearest | 0x00420040 | 225 | 91/89 | 65.56% | 7/89 |  | gameplay-target-search |
| wip | projectile_spawn | 0x00420440 | 400 | 118/126 | 64.75% | 0/126 |  | gameplay-projectile |
| match | projectile_reset_pools | 0x004205d0 | 37 | 11/11 | 100.00% | 11/11 |  | gameplay-pool-reset |
| wip | creature_find_in_radius | 0x004206a0 | 133 | 51/47 | 40.82% | 0/47 |  | gameplay-target-search |
| wip | creature_reset_all | 0x004281e0 | 46 | 12/13 | 80.00% | 2/13 |  | gameplay-creature-reset |
| match | creatures_none_active | 0x00428210 | 40 | 12/12 | 100.00% | 12/12 | msvc6.5pp /O2 /G6 /W3 /GR- | gameplay-creature-scan |
| match | bonus_label_for_entry | 0x00429580 | 99 | 30/30 | 100.00% | 30/30 |  | gameplay-bonus-label |
| wip | perk_select_random | 0x0042fbd0 | 89 | 32/32 | 96.88% | 28/32 | msvc6.5pp /O2 /G6 /W3 /GR- | gameplay-perk-rng |
| match | perk_count_get | 0x0042fcf0 | 12 | 3/3 | 100.00% | 3/3 |  | gameplay-perk-count |
| match | creature_spawn_slot_alloc | 0x00430ad0 | 30 | 10/10 | 100.00% | 10/10 | msvc6.5pp /O2 /G6 /W3 /GR- | gameplay-spawn-slots |
| wip | creature_spawn_template | 0x00430af0 | 14099 | 930/3159 | 20.05% | 20/3159 |  | gameplay-spawn-switch |
| wip | weapon_pick_random_available | 0x00452cd0 | 107 | 36/36 | 97.22% | 6/36 |  | gameplay-weapon-rng |
| wip | weapon_refresh_available | 0x00452e40 | 161 | 48/48 | 91.67% | 8/48 |  | gameplay-weapon-unlocks |

## grim.dll

**7/1175** functions, **114/289897** bytes (**0.0%**), **7/7** scratches at 100%.

| state | function | address | bytes | insns | match | prefix | build | note |
|---|---|---|---:|---:|---:|---:|---|---|
| match | grim_noop | 0x10001160 | 1 | 1/1 | 100.00% | 1/1 |  | smoke |
| match | grim_get_error_text | 0x10006ca0 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | grim_get_time_ms | 0x10006e40 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | grim_get_frame_dt | 0x10006e60 | 33 | 9/9 | 100.00% | 9/9 |  | branch-x87 |
| match | grim_is_mouse_button_down | 0x10007410 | 38 | 11/11 | 100.00% | 11/11 |  | branch-call-stdcall |
| match | grim_get_mouse_x | 0x10007510 | 7 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | grim_get_mouse_wheel_delta | 0x10007560 | 23 | 7/7 | 100.00% | 7/7 |  | branch-x87 |
