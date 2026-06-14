# Matching Status

Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.

**13/2161** functions matched, **213/675651** code bytes (**0.0%**). Byte totals are manifest function extents with terminal padding trimmed.

## Images

| image | functions | bytes | code | scratches |
|---|---:|---:|---:|---:|
| crimsonland.exe | 6/986 | 99/385754 | 0.0% | 6/16 |
| grim.dll | 7/1175 | 114/289897 | 0.0% | 7/7 |

## crimsonland.exe

**6/986** functions, **99/385754** bytes (**0.0%**), **6/16** scratches at 100%.

| state | function | address | bytes | insns | match | prefix | build | note |
|---|---|---|---:|---:|---:|---:|---|---|
| match | console_input_clear | 0x00401030 | 18 | 5/5 | 100.00% | 5/5 |  | smoke |
| match | console_input_buffer | 0x00401050 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | console_cmd_argc_get | 0x00401150 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| wip | player_start_reload | 0x00413430 | 263 | 67/67 | 94.03% | 29/67 |  | gameplay-reload |
| wip | player_heading_approach_target | 0x00413540 | 354 | 96/95 | 28.27% | 2/95 |  | gameplay-angle-x87 |
| match | vec2_length | 0x00417660 | 26 | 12/12 | 100.00% | 12/12 |  | x87-fsqrt |
| match | game_sequence_get | 0x0041df60 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| wip | player_apply_move_with_spawn_avoidance | 0x0041e290 | 356 | 133/131 | 61.36% | 0/131 |  | gameplay-movement |
| wip | bonus_alloc_slot | 0x0041f580 | 46 | 17/14 | 58.06% | 0/14 |  | gameplay-bonus-pool |
| wip | creature_find_nearest | 0x00420040 | 225 | 91/89 | 64.44% | 7/89 |  | gameplay-target-search |
| wip | projectile_spawn | 0x00420440 | 400 | 118/126 | 63.11% | 0/126 |  | gameplay-projectile |
| match | projectile_reset_pools | 0x004205d0 | 37 | 11/11 | 100.00% | 11/11 |  | gameplay-pool-reset |
| wip | creature_find_in_radius | 0x004206a0 | 133 | 51/47 | 40.82% | 0/47 |  | gameplay-target-search |
| wip | creature_reset_all | 0x004281e0 | 46 | 12/13 | 80.00% | 2/13 |  | gameplay-creature-reset |
| wip | creatures_none_active | 0x00428210 | 40 | 15/12 | 44.44% | 0/12 |  | gameplay-creature-scan |
| wip | creature_spawn_slot_alloc | 0x00430ad0 | 30 | 14/10 | 58.33% | 0/10 |  | gameplay-spawn-slots |

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
