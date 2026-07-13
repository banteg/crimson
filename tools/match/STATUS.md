# Matching Status

Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.

**67/2161** functions matched, **9483/675651** code bytes (**1.4%**). Byte totals are manifest function extents with terminal padding trimmed.

## Images

| image | functions | bytes | code | scratches |
|---|---:|---:|---:|---:|
| crimsonland.exe | 41/986 | 6096/385754 | 1.6% | 41/57 |
| grim.dll | 26/1175 | 3387/289897 | 1.2% | 26/26 |

## crimsonland.exe

**41/986** functions, **6096/385754** bytes (**1.6%**), **41/57** scratches verified.

| state | function | address | bytes | insns | match | prefix | refs ok/?/! | build | note |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| match | console_input_clear | 0x00401030 | 18 | 5/5 | 100.00% | 5/5 | 3/0/0 |  | smoke |
| match | console_input_buffer | 0x00401050 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | console_cmd_argc_get | 0x00401150 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| wip | bonus_apply | 0x00409890 | 2693 | 664/668 | 65.32% | 27/668 | 161/0/14 |  | gameplay-bonus-switch |
| match | gameplay_run_state_init | 0x004120b0 | 172 | 44/44 | 100.00% | 44/44 | 20/0/0 |  | gameplay-run-initialization |
| wip | bonus_pick_random_type | 0x00412470 | 484 | 162/162 | 67.28% | 37/162 | 20/0/0 |  | gameplay-bonus-selection |
| match | player_start_reload | 0x00413430 | 263 | 67/67 | 100.00% | 67/67 | 28/0/0 |  | gameplay-reload |
| match | player_heading_approach_target | 0x00413540 | 354 | 95/95 | 100.00% | 95/95 | 27/0/0 |  | gameplay-angle-x87 |
| match | vec2_sub | 0x00417640 | 26 | 9/9 | 100.00% | 9/9 | 0/0/0 |  | x87-vector-subtract |
| match | vec2_length | 0x00417660 | 26 | 12/12 | 100.00% | 12/12 | 0/0/0 |  | x87-fsqrt |
| match | game_sequence_get | 0x0041df60 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | vec2_add | 0x0041e270 | 26 | 10/10 | 100.00% | 10/10 | 0/0/0 |  | x87-vector-add |
| match | player_apply_move_with_spawn_avoidance | 0x0041e290 | 356 | 131/131 | 100.00% | 131/131 | 8/0/0 |  | gameplay-movement |
| match | vec2_add_inplace | 0x0041e400 | 26 | 10/10 | 100.00% | 10/10 | 0/0/0 |  | x87-vector-add |
| match | bonus_alloc_slot | 0x0041f580 | 46 | 14/14 | 100.00% | 14/14 | 4/0/0 |  | gameplay-bonus-pool |
| wip | bonus_spawn_at_pos | 0x0041f790 | 309 | 100/99 | 88.44% | 0/99 | 14/0/0 |  | gameplay-bonus-spawn |
| wip | bonus_try_spawn_on_kill | 0x0041f8d0 | 730 | 201/207 | 88.24% | 6/207 | 47/0/0 |  | gameplay-bonus-drop |
| match | fx_spawn_sprite | 0x0041fbb0 | 175 | 48/48 | 100.00% | 48/48 | 16/0/0 |  | gameplay-sprite-effect-spawn |
| match | weapon_table_entry | 0x0041fc60 | 19 | 6/6 | 100.00% | 6/6 | 1/0/0 |  | gameplay-weapon-table |
| wip | player_reset_all | 0x0041fc80 | 584 | 120/127 | 37.25% | 1/127 | 15/0/2 |  | gameplay-player-reset |
| wip | creature_find_nearest | 0x00420040 | 225 | 91/89 | 74.44% | 7/89 | 3/0/1 |  | gameplay-target-search |
| match | fx_spawn_particle | 0x00420130 | 264 | 67/67 | 100.00% | 67/67 | 18/0/0 |  | gameplay-particle-spawn |
| match | fx_spawn_particle_slow | 0x00420240 | 274 | 67/67 | 100.00% | 67/67 | 19/0/0 |  | gameplay-particle-spawn |
| wip | fx_spawn_secondary_projectile | 0x00420360 | 218 | 63/65 | 84.38% | 0/65 | 13/0/0 |  | gameplay-secondary-projectile |
| wip | projectile_spawn | 0x00420440 | 400 | 118/126 | 67.21% | 0/126 | 11/0/0 |  | gameplay-projectile |
| match | projectile_reset_pools | 0x004205d0 | 37 | 11/11 | 100.00% | 11/11 | 4/0/0 |  | gameplay-pool-reset |
| wip | creatures_apply_radius_damage | 0x00420600 | 159 | 58/57 | 83.48% | 11/57 | 4/0/2 |  | gameplay-radius-damage |
| wip | creature_find_in_radius | 0x004206a0 | 133 | 48/47 | 61.05% | 4/47 | 3/0/2 |  | gameplay-target-search |
| wip | player_find_in_radius | 0x00420730 | 133 | 55/54 | 75.23% | 9/54 | 4/0/1 |  | gameplay-target-search |
| wip | plaguebearer_spread_infection | 0x00425d80 | 203 | 66/64 | 80.00% | 5/64 | 14/0/0 |  | gameplay-plaguebearer-spread |
| match | player_take_damage | 0x00425e50 | 969 | 267/267 | 100.00% | 267/267 | 73/0/0 |  | gameplay-player-damage |
| match | creature_alloc_slot | 0x00428140 | 145 | 39/39 | 100.00% | 39/39 | 14/0/0 |  |  |
| match | creature_reset_all | 0x004281e0 | 46 | 13/13 | 100.00% | 13/13 | 3/0/0 |  | gameplay-creature-reset |
| match | creatures_none_active | 0x00428210 | 40 | 12/12 | 100.00% | 12/12 | 4/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-creature-scan |
| wip | creature_spawn | 0x00428240 | 334 | 79/79 | 86.08% | 7/79 | 27/0/0 |  | gameplay-creature-spawn |
| match | bonus_label_for_entry | 0x00429580 | 99 | 30/30 | 100.00% | 30/30 | 11/0/0 |  | gameplay-bonus-label |
| match | effect_init_entry | 0x0042de80 | 143 | 36/36 | 100.00% | 36/36 | 0/0/0 |  | gameplay-effect-pool |
| match | effect_defaults_reset | 0x0042df10 | 355 | 59/59 | 100.00% | 59/59 | 29/0/0 |  | gameplay-effect-pool-reset |
| match | effect_free | 0x0042e080 | 29 | 6/6 | 100.00% | 6/6 | 2/0/0 |  | gameplay-effect-pool |
| match | effect_select_texture | 0x0042e0a0 | 113 | 35/35 | 100.00% | 35/35 | 6/0/0 |  | gameplay-effect-texture |
| match | effects_update | 0x0042e710 | 267 | 85/85 | 100.00% | 85/85 | 10/0/0 |  | gameplay-effect-lifecycle |
| match | effect_spawn_ion_hit_core | 0x0042f270 | 191 | 32/32 | 100.00% | 32/32 | 16/0/0 |  | gameplay-effect-spawn |
| match | effect_spawn_plasma_hit_core | 0x0042f330 | 185 | 31/31 | 100.00% | 31/31 | 15/0/0 |  | gameplay-effect-spawn |
| wip | effect_spawn_splitter_hit_burst | 0x0042f3f0 | 333 | 75/75 | 82.67% | 3/75 | 21/0/1 |  | gameplay-effect-spawn |
| match | perk_can_offer | 0x0042fb10 | 185 | 55/55 | 100.00% | 55/55 | 17/0/0 |  | gameplay-perk-eligibility |
| match | perk_select_random | 0x0042fbd0 | 89 | 32/32 | 100.00% | 32/32 | 8/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-perk-rng |
| wip | perks_rebuild_available | 0x0042fc30 | 181 | 52/52 | 73.08% | 9/52 | 16/0/0 |  | gameplay-perk-unlocks |
| match | perk_count_get | 0x0042fcf0 | 12 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | gameplay-perk-count |
| match | creature_spawn_slot_alloc | 0x00430ad0 | 30 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-spawn-slots |
| wip | creature_spawn_template | 0x00430af0 | 14099 | 2722/3159 | 58.09% | 23/3159 | 308/2/1 |  | gameplay-spawn-switch |
| match | creature_spawn_tinted | 0x00444810 | 364 | 92/92 | 100.00% | 92/92 | 34/0/0 |  | gameplay-typo-creature-spawn |
| match | vec2_add_out | 0x0044ecf0 | 26 | 9/9 | 100.00% | 9/9 | 0/0/0 |  | x87-vector-add |
| match | weapon_pick_random_available | 0x00452cd0 | 107 | 36/36 | 100.00% | 36/36 | 8/0/0 |  | gameplay-weapon-rng |
| match | weapon_assign_player | 0x00452d40 | 254 | 61/61 | 100.00% | 61/61 | 26/0/0 |  | gameplay-weapon-assignment |
| match | weapon_refresh_available | 0x00452e40 | 161 | 48/48 | 100.00% | 48/48 | 17/0/0 |  | gameplay-weapon-unlocks |
| match | float_near_equal | 0x00452ef0 | 45 | 17/17 | 100.00% | 17/17 | 2/0/0 | msvc6.5pp /O1 /GB /W3 /GR- | math-float-epsilon |
| match | vec2_normalize_safe | 0x00455587 | 141 | 57/57 | 100.00% | 57/57 | 3/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | vector-safe-normalize |

## grim.dll

**26/1175** functions, **3387/289897** bytes (**1.2%**), **26/26** scratches verified.

| state | function | address | bytes | insns | match | prefix | refs ok/?/! | build | note |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| match | grim_noop | 0x10001160 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | smoke |
| match | grim_get_error_text | 0x10006ca0 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_get_time_ms | 0x10006e40 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_get_frame_dt | 0x10006e60 | 33 | 9/9 | 100.00% | 9/9 | 4/0/0 |  | branch-x87 |
| match | grim_is_mouse_button_down | 0x10007410 | 38 | 11/11 | 100.00% | 11/11 | 3/0/0 |  | branch-call-stdcall |
| match | grim_get_mouse_x | 0x10007510 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_get_mouse_wheel_delta | 0x10007560 | 23 | 7/7 | 100.00% | 7/7 | 3/0/0 |  | branch-x87 |
| match | grim_bind_texture | 0x10007830 | 58 | 20/20 | 100.00% | 20/20 | 3/0/0 |  | grim2d-texture-binding |
| match | grim_draw_rect_filled | 0x100078e0 | 205 | 72/72 | 100.00% | 72/72 | 6/0/0 |  | grim2d-filled-rectangle |
| match | grim_begin_batch | 0x10007ac0 | 94 | 27/27 | 100.00% | 27/27 | 9/0/0 |  | grim2d-batch-lifecycle |
| match | grim_end_batch | 0x10007b20 | 104 | 36/36 | 100.00% | 36/36 | 8/0/0 |  | grim2d-batch-lifecycle |
| match | grim_set_color | 0x10007f90 | 166 | 42/42 | 100.00% | 42/42 | 16/0/0 |  | grim2d-packed-color |
| match | grim_set_color_ptr | 0x10008040 | 104 | 25/25 | 100.00% | 25/25 | 12/0/0 |  | grim2d-packed-color-pointer |
| match | grim_set_color_slot | 0x100081c0 | 109 | 27/27 | 100.00% | 27/27 | 9/0/0 |  | grim2d-packed-color-slot |
| match | grim_set_uv | 0x10008350 | 74 | 17/17 | 100.00% | 17/17 | 8/0/0 |  | grim2d-uv-rectangle |
| match | grim_set_uv_point | 0x100083a0 | 29 | 6/6 | 100.00% | 6/6 | 2/0/0 |  | grim2d-uv-point |
| match | grim_flush_batch | 0x100083c0 | 107 | 37/37 | 100.00% | 37/37 | 8/0/0 |  | grim2d-batch-lifecycle |
| match | grim_submit_vertices_offset_color | 0x10008430 | 168 | 54/54 | 100.00% | 54/54 | 9/0/0 |  | grim2d-vertex-submit-offset-color |
| match | grim_submit_vertices_transform_color | 0x100084e0 | 218 | 72/72 | 100.00% | 72/72 | 10/0/0 |  | grim2d-vertex-submit-transform-color |
| match | grim_submit_vertices_transform | 0x100085c0 | 192 | 64/64 | 100.00% | 64/64 | 9/0/0 |  | grim2d-vertex-submit-transform |
| match | grim_submit_vertices_offset | 0x10008680 | 153 | 50/50 | 100.00% | 50/50 | 8/0/0 |  | grim2d-vertex-submit-offset |
| match | grim_draw_quad_xy | 0x10008720 | 34 | 14/14 | 100.00% | 14/14 | 0/0/0 |  | grim2d-quad-xy-wrapper |
| match | grim_draw_quad | 0x10008b10 | 800 | 195/195 | 100.00% | 195/195 | 68/0/0 |  | grim2d-quad-batching |
| match | grim_draw_quad_points | 0x10009080 | 554 | 130/130 | 100.00% | 130/130 | 59/0/0 |  | grim2d-quad-points |
| match | grim_draw_text_mono_fmt | 0x10009940 | 52 | 16/16 | 100.00% | 16/16 | 3/0/0 |  | grim2d-mono-text-format-wrapper |
| match | grim_draw_text_small_fmt | 0x10009980 | 52 | 16/16 | 100.00% | 16/16 | 3/0/0 |  | grim2d-small-text-format-wrapper |
