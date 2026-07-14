# Matching Status

Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.

**177/2161** functions matched, **26341/675651** code bytes (**3.9%**). Byte totals are manifest function extents with terminal padding trimmed.

## Images

| image | functions | bytes | code | scratches |
|---|---:|---:|---:|---:|
| crimsonland.exe | 45/986 | 6894/385754 | 1.8% | 45/59 |
| grim.dll | 132/1175 | 19447/289897 | 6.7% | 132/137 |

## crimsonland.exe

**45/986** functions, **6894/385754** bytes (**1.8%**), **45/59** scratches verified.

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
| wip | creature_find_nearest | 0x00420040 | 225 | 92/89 | 79.56% | 7/89 | 3/0/1 |  | gameplay-target-search |
| match | fx_spawn_particle | 0x00420130 | 264 | 67/67 | 100.00% | 67/67 | 18/0/0 |  | gameplay-particle-spawn |
| match | fx_spawn_particle_slow | 0x00420240 | 274 | 67/67 | 100.00% | 67/67 | 19/0/0 |  | gameplay-particle-spawn |
| wip | fx_spawn_secondary_projectile | 0x00420360 | 218 | 63/65 | 84.38% | 0/65 | 13/0/0 |  | gameplay-secondary-projectile |
| wip | projectile_spawn | 0x00420440 | 400 | 118/126 | 67.21% | 0/126 | 11/0/0 |  | gameplay-projectile |
| match | projectile_reset_pools | 0x004205d0 | 37 | 11/11 | 100.00% | 11/11 | 4/0/0 |  | gameplay-pool-reset |
| wip | creatures_apply_radius_damage | 0x00420600 | 159 | 58/57 | 83.48% | 11/57 | 4/0/2 |  | gameplay-radius-damage |
| wip | creature_find_in_radius | 0x004206a0 | 133 | 49/47 | 70.83% | 4/47 | 3/0/2 |  | gameplay-target-search |
| wip | player_find_in_radius | 0x00420730 | 133 | 55/54 | 77.06% | 9/54 | 4/0/1 |  | gameplay-target-search |
| match | plaguebearer_spread_infection | 0x00425d80 | 203 | 64/64 | 100.00% | 64/64 | 14/0/0 |  | gameplay-plaguebearer-spread |
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
| match | effect_spawn_splitter_hit_burst | 0x0042f3f0 | 333 | 75/75 | 100.00% | 75/75 | 23/0/0 |  | gameplay-effect-spawn |
| match | perk_can_offer | 0x0042fb10 | 185 | 55/55 | 100.00% | 55/55 | 17/0/0 |  | gameplay-perk-eligibility |
| match | perk_select_random | 0x0042fbd0 | 89 | 32/32 | 100.00% | 32/32 | 8/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-perk-rng |
| wip | perks_rebuild_available | 0x0042fc30 | 181 | 52/52 | 73.08% | 9/52 | 16/0/0 |  | gameplay-perk-unlocks |
| match | perk_count_get | 0x0042fcf0 | 12 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | gameplay-perk-count |
| match | creature_spawn_slot_alloc | 0x00430ad0 | 30 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-spawn-slots |
| wip | creature_spawn_template | 0x00430af0 | 14099 | 2722/3159 | 58.09% | 23/3159 | 308/2/1 |  | gameplay-spawn-switch |
| match | creature_spawn_tinted | 0x00444810 | 364 | 92/92 | 100.00% | 92/92 | 34/0/0 |  | gameplay-typo-creature-spawn |
| match | input_primary_just_pressed | 0x00446030 | 188 | 62/62 | 100.00% | 62/62 | 14/0/0 |  | input-primary-edge |
| match | input_primary_is_down | 0x004460f0 | 74 | 24/24 | 100.00% | 24/24 | 5/0/0 |  | input-primary-held |
| match | vec2_add_out | 0x0044ecf0 | 26 | 9/9 | 100.00% | 9/9 | 0/0/0 |  | x87-vector-add |
| match | weapon_pick_random_available | 0x00452cd0 | 107 | 36/36 | 100.00% | 36/36 | 8/0/0 |  | gameplay-weapon-rng |
| match | weapon_assign_player | 0x00452d40 | 254 | 61/61 | 100.00% | 61/61 | 26/0/0 |  | gameplay-weapon-assignment |
| match | weapon_refresh_available | 0x00452e40 | 161 | 48/48 | 100.00% | 48/48 | 17/0/0 |  | gameplay-weapon-unlocks |
| match | float_near_equal | 0x00452ef0 | 45 | 17/17 | 100.00% | 17/17 | 2/0/0 | msvc6.5pp /O1 /GB /W3 /GR- | math-float-epsilon |
| match | vec2_normalize_safe | 0x00455587 | 141 | 57/57 | 100.00% | 57/57 | 3/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | vector-safe-normalize |

## grim.dll

**132/1175** functions, **19447/289897** bytes (**6.7%**), **132/137** scratches verified.

| state | function | address | bytes | insns | match | prefix | refs ok/?/! | build | note |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| match | grim_noop | 0x10001160 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | smoke |
| match | grim_window_create | 0x10002680 | 497 | 142/142 | 100.00% | 142/142 | 46/0/0 |  | grim-window-creation |
| match | grim_window_destroy | 0x10002880 | 66 | 22/22 | 100.00% | 22/22 | 8/0/0 |  | grim-window-teardown |
| match | grim_backup_textures | 0x100028d0 | 610 | 219/219 | 100.00% | 219/219 | 41/0/0 |  | grim-texture-backup |
| match | grim_restore_textures | 0x10002b40 | 432 | 161/161 | 100.00% | 161/161 | 26/0/0 |  | grim-texture-restore |
| match | grim_try_reset_device | 0x10002cf0 | 609 | 205/205 | 100.00% | 205/205 | 48/0/0 |  | grim-device-reset |
| match | grim_app_cleanup | 0x10002f60 | 26 | 10/10 | 100.00% | 10/10 | 1/0/0 |  | grim-app-gdi-cleanup |
| match | grim_app_tick | 0x10002f80 | 64 | 29/29 | 100.00% | 29/29 | 1/0/0 |  | grim-app-30ms-tick |
| match | grim_app_init | 0x10002fc0 | 185 | 54/54 | 100.00% | 54/54 | 13/0/0 |  | grim-app-runtime-init |
| match | grim_app_shutdown | 0x10003080 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | grim-app-shutdown-thunk |
| match | grim_app_pump | 0x10003090 | 20 | 6/6 | 100.00% | 6/6 | 3/0/0 |  | grim-app-30ms-pump |
| match | grim_run_loop | 0x10003c00 | 608 | 174/174 | 100.00% | 174/174 | 61/0/0 |  | grim-win32-frame-loop |
| match | grim_d3d_init | 0x10003e60 | 1046 | 323/323 | 100.00% | 323/323 | 104/0/0 | msvc6.5 /O2 /GB /W3 /GR- /MD | grim-direct3d-initialization |
| wip | grim_d3d_shutdown | 0x10004280 | 196 | 72/72 | 87.50% | 40/72 | 15/0/0 |  | grim-d3d-resource-teardown |
| match | grim_create_geometry_buffers | 0x10004350 | 387 | 107/107 | 100.00% | 107/107 | 32/0/0 |  | grim-geometry-buffer-creation |
| match | grim_release_geometry_buffers | 0x100044e0 | 51 | 15/15 | 100.00% | 15/15 | 4/0/0 |  | grim-geometry-buffer-teardown |
| match | grim_apply_render_state | 0x10004520 | 720 | 232/232 | 100.00% | 232/232 | 41/0/0 |  | grim-render-state-restore |
| match | grim_is_texture_format_supported | 0x100047f0 | 51 | 19/19 | 100.00% | 19/19 | 4/0/0 |  | grim-texture-format-probe |
| match | grim_select_texture_format | 0x10004830 | 232 | 67/67 | 100.00% | 67/67 | 17/0/0 |  | grim-texture-format-selection |
| match | grim_timing_init | 0x10004920 | 74 | 13/13 | 100.00% | 13/13 | 10/0/0 |  | grim-frame-timing-init |
| match | grim_timing_update | 0x10004970 | 216 | 53/53 | 100.00% | 53/53 | 23/0/0 |  | grim-frame-timing-update |
| match | grim_texture_init | 0x10004a50 | 83 | 38/38 | 100.00% | 38/38 | 1/0/0 |  | grim-texture-constructor |
| match | grim_texture_release | 0x10004ab0 | 66 | 25/25 | 100.00% | 25/25 | 1/0/0 |  | grim-texture-destructor |
| match | grim_path_has_extension | 0x10004b00 | 99 | 50/50 | 100.00% | 50/50 | 0/0/0 |  | grim-texture-extension |
| wip | grim_decode_jaz_texture | 0x10004b70 | 785 | 252/252 | 86.51% | 32/252 | 6/15/0 | msvc6.5 /O2 /GB /W3 /GR- /GX /MD | grim-jaz-texture-decode |
| match | grim_jaz_jpeg_error_exit | 0x10004e90 | 41 | 14/14 | 100.00% | 14/14 | 1/0/0 | msvc6.5 /O2 /GB /W3 /GR- /MD | grim-jaz-jpeg-error |
| wip | grim_texture_load_file | 0x10004ec0 | 591 | 223/235 | 64.19% | 0/235 | 24/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX /MD | grim-texture-file-decode |
| match | grim_texture_name_equals | 0x10005110 | 93 | 44/44 | 100.00% | 44/44 | 0/0/0 |  | grim-texture-name |
| match | grim_find_texture_by_name | 0x10005170 | 68 | 33/33 | 100.00% | 33/33 | 4/0/0 |  | grim-texture-name-lookup |
| match | grim_find_free_texture_slot | 0x100051c0 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 |  | grim-texture-slot-allocation |
| match | grim_load_texture_internal | 0x100051e0 | 265 | 80/80 | 100.00% | 80/80 | 14/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | grim-texture-file-load |
| match | grim_lookup_blob_load | 0x10005a40 | 146 | 51/51 | 100.00% | 51/51 | 15/0/0 |  | grim-lookup-blob-lifecycle |
| match | grim_lookup_blob_find | 0x10005ae0 | 146 | 66/66 | 100.00% | 66/66 | 4/0/0 |  | grim-lookup-blob-search |
| match | grim_lookup_blob_size_for_path | 0x10005b80 | 146 | 66/66 | 100.00% | 66/66 | 4/0/0 |  | grim-lookup-blob-size |
| match | grim_set_key_char_buffer | 0x10005c20 | 32 | 7/7 | 100.00% | 7/7 | 3/0/0 |  | grim2d-key-char-buffer |
| match | grim_get_key_char | 0x10005c40 | 52 | 22/22 | 100.00% | 22/22 | 4/0/0 |  | grim2d-key-char-fifo |
| match | grim_release | 0x10005c80 | 8 | 4/4 | 100.00% | 4/4 | 1/0/0 |  | grim2d-object-release |
| match | grim_set_paused | 0x10005c90 | 12 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | grim2d-pause-state |
| match | grim_get_version | 0x10005ca0 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim2d-version |
| match | grim_save_screenshot | 0x10005cb0 | 140 | 56/56 | 100.00% | 56/56 | 5/0/0 |  | grim2d-front-buffer-capture |
| match | grim_apply_config | 0x10005d40 | 367 | 124/124 | 100.00% | 124/124 | 25/0/0 |  | grim2d-configuration-dialog |
| match | grim_init_system | 0x10005eb0 | 318 | 93/93 | 100.00% | 93/93 | 32/0/0 |  | grim2d-system-initialization |
| match | grim_shutdown | 0x10005ff0 | 38 | 8/8 | 100.00% | 8/8 | 7/0/0 |  | grim2d-system-shutdown |
| match | grim_apply_settings | 0x10006020 | 8 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | grim2d-run-loop-wrapper |
| match | grim_get_config_var | 0x10006c30 | 102 | 32/32 | 100.00% | 32/32 | 5/0/0 |  | grim2d-get-config-var |
| match | grim_get_error_text | 0x10006ca0 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_clear_color | 0x10006cb0 | 150 | 45/45 | 100.00% | 45/45 | 11/0/0 |  | grim2d-device-clear |
| match | grim_set_render_target | 0x10006d50 | 240 | 89/89 | 100.00% | 89/89 | 19/0/0 |  | grim2d-render-target-switch |
| match | grim_get_time_ms | 0x10006e40 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_set_time_ms | 0x10006e50 | 12 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | grim2d-time-state |
| match | grim_get_frame_dt | 0x10006e60 | 33 | 9/9 | 100.00% | 9/9 | 4/0/0 |  | branch-x87 |
| match | grim_get_fps | 0x10006e90 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim2d-fps-state |
| match | grim_joystick_up_active | 0x10006ea0 | 78 | 23/23 | 100.00% | 23/23 | 3/0/0 |  | grim-joystick-direction |
| match | grim_joystick_down_active | 0x10006ef0 | 74 | 21/21 | 100.00% | 21/21 | 3/0/0 |  | grim-joystick-direction |
| match | grim_joystick_left_active | 0x10006f40 | 78 | 23/23 | 100.00% | 23/23 | 3/0/0 |  | grim-joystick-direction |
| match | grim_joystick_right_active | 0x10006f90 | 74 | 21/21 | 100.00% | 21/21 | 3/0/0 |  | grim-joystick-direction |
| wip | grim_is_key_active | 0x10006fe0 | 456 | 174/175 | 73.93% | 2/175 | 7/0/1 |  | grim-input-key-router |
| match | grim_get_config_float | 0x100071b0 | 264 | 88/88 | 100.00% | 88/88 | 13/0/0 |  | grim-input-float-router |
| match | grim_get_slot_float | 0x100072c0 | 14 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | grim-slot-state |
| match | grim_get_slot_int | 0x100072d0 | 14 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | grim-slot-state |
| match | grim_set_slot_float | 0x100072e0 | 18 | 4/4 | 100.00% | 4/4 | 1/0/0 |  | grim-slot-state |
| match | grim_set_slot_int | 0x10007300 | 18 | 4/4 | 100.00% | 4/4 | 1/0/0 |  | grim-slot-state |
| match | grim_is_key_down | 0x10007320 | 16 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | grim2d-key-state |
| match | grim_flush_input | 0x10007330 | 91 | 34/34 | 100.00% | 34/34 | 5/0/0 |  | grim2d-input-flush |
| match | grim_was_key_pressed | 0x10007390 | 119 | 31/31 | 100.00% | 31/31 | 10/0/0 |  | grim2d-key-repeat |
| match | grim_is_mouse_button_down | 0x10007410 | 38 | 11/11 | 100.00% | 11/11 | 3/0/0 |  | grim2d-mouse-button-state |
| match | grim_was_mouse_button_pressed | 0x10007440 | 131 | 51/51 | 100.00% | 51/51 | 7/0/0 |  | grim2d-mouse-edge |
| match | grim_get_mouse_dx | 0x100074d0 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim-mouse-motion |
| match | grim_get_mouse_dy | 0x100074e0 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim-mouse-motion |
| match | grim_get_mouse_dx_indexed | 0x100074f0 | 8 | 3/3 | 100.00% | 3/3 | 0/0/0 |  | grim-mouse-motion-forwarder |
| match | grim_get_mouse_dy_indexed | 0x10007500 | 8 | 3/3 | 100.00% | 3/3 | 0/0/0 |  | grim-mouse-motion-forwarder |
| match | grim_get_mouse_x | 0x10007510 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | grim_get_mouse_y | 0x10007520 | 7 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim-mouse-position |
| match | grim_set_mouse_pos | 0x10007530 | 37 | 9/9 | 100.00% | 9/9 | 4/0/0 |  | grim-mouse-position |
| match | grim_get_mouse_wheel_delta | 0x10007560 | 23 | 7/7 | 100.00% | 7/7 | 3/0/0 |  | branch-x87 |
| match | grim_get_joystick_x | 0x10007580 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim-joystick-state |
| match | grim_get_joystick_y | 0x10007590 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim-joystick-state |
| match | grim_get_joystick_z | 0x100075a0 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | grim-joystick-state |
| match | grim_get_joystick_pov | 0x100075b0 | 14 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | grim-joystick-state |
| match | grim_is_joystick_button_down | 0x100075c0 | 16 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | grim-joystick-button-wrapper |
| match | grim_create_texture | 0x100075d0 | 257 | 81/81 | 100.00% | 81/81 | 13/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | grim2d-texture-create |
| match | grim_load_texture | 0x100076e0 | 21 | 7/7 | 100.00% | 7/7 | 1/0/0 |  | grim2d-texture-load-wrapper |
| match | grim_destroy_texture | 0x10007700 | 64 | 20/20 | 100.00% | 20/20 | 6/0/0 |  | grim2d-texture-destruction |
| match | grim_get_texture_handle | 0x10007740 | 16 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | grim2d-texture-lookup |
| match | grim_save_texture | 0x10007750 | 50 | 18/18 | 100.00% | 18/18 | 2/0/0 |  | grim2d-texture-save |
| match | grim_recreate_texture | 0x10007790 | 157 | 57/57 | 100.00% | 57/57 | 8/0/0 |  | grim2d-texture-recreate |
| match | grim_bind_texture | 0x10007830 | 58 | 20/20 | 100.00% | 20/20 | 3/0/0 |  | grim2d-texture-binding |
| match | grim_draw_fullscreen_quad | 0x10007870 | 109 | 32/32 | 100.00% | 32/32 | 2/0/0 |  | grim2d-fullscreen-quad |
| match | grim_draw_rect_filled | 0x100078e0 | 205 | 72/72 | 100.00% | 72/72 | 6/0/0 |  | grim2d-filled-rectangle |
| match | grim_draw_fullscreen_color | 0x100079b0 | 259 | 83/83 | 100.00% | 83/83 | 8/0/0 |  | grim2d-fullscreen-color |
| match | grim_begin_batch | 0x10007ac0 | 94 | 27/27 | 100.00% | 27/27 | 9/0/0 |  | grim2d-batch-lifecycle |
| match | grim_end_batch | 0x10007b20 | 104 | 36/36 | 100.00% | 36/36 | 8/0/0 |  | grim2d-batch-lifecycle |
| match | grim_draw_circle_filled | 0x10007b90 | 432 | 115/115 | 100.00% | 115/115 | 32/0/0 |  | grim2d-filled-circle |
| match | grim_draw_circle_outline | 0x10007d40 | 462 | 120/120 | 100.00% | 120/120 | 31/0/0 |  | grim2d-circle-outline |
| match | grim_set_rotation | 0x10007f30 | 85 | 19/19 | 100.00% | 19/19 | 11/0/0 |  | grim2d-rotation-matrix |
| match | grim_set_color | 0x10007f90 | 166 | 42/42 | 100.00% | 42/42 | 16/0/0 |  | grim2d-packed-color |
| match | grim_set_color_ptr | 0x10008040 | 104 | 25/25 | 100.00% | 25/25 | 12/0/0 |  | grim2d-packed-color-pointer |
| match | grim_draw_line | 0x100080b0 | 134 | 40/40 | 100.00% | 40/40 | 13/0/0 |  | grim2d-line-vector |
| match | grim_draw_line_quad | 0x10008150 | 99 | 42/42 | 100.00% | 42/42 | 0/0/0 |  | grim2d-line-quad |
| match | grim_set_color_slot | 0x100081c0 | 109 | 27/27 | 100.00% | 27/27 | 9/0/0 |  | grim2d-packed-color-slot |
| match | grim_set_atlas_frame | 0x10008230 | 139 | 31/31 | 100.00% | 31/31 | 15/0/0 |  | grim2d-atlas-frame |
| match | grim_set_sub_rect | 0x100082c0 | 143 | 31/31 | 100.00% | 31/31 | 15/0/0 |  | grim2d-atlas-sub-rectangle |
| match | grim_set_uv | 0x10008350 | 74 | 17/17 | 100.00% | 17/17 | 8/0/0 |  | grim2d-uv-rectangle |
| match | grim_set_uv_point | 0x100083a0 | 29 | 6/6 | 100.00% | 6/6 | 2/0/0 |  | grim2d-uv-point |
| match | grim_flush_batch | 0x100083c0 | 107 | 37/37 | 100.00% | 37/37 | 8/0/0 |  | grim2d-batch-lifecycle |
| match | grim_submit_vertices_offset_color | 0x10008430 | 168 | 54/54 | 100.00% | 54/54 | 9/0/0 |  | grim2d-vertex-submit-offset-color |
| match | grim_submit_vertices_transform_color | 0x100084e0 | 218 | 72/72 | 100.00% | 72/72 | 10/0/0 |  | grim2d-vertex-submit-transform-color |
| match | grim_submit_vertices_transform | 0x100085c0 | 192 | 64/64 | 100.00% | 64/64 | 9/0/0 |  | grim2d-vertex-submit-transform |
| match | grim_submit_vertices_offset | 0x10008680 | 153 | 50/50 | 100.00% | 50/50 | 8/0/0 |  | grim2d-vertex-submit-offset |
| match | grim_draw_quad_xy | 0x10008720 | 34 | 14/14 | 100.00% | 14/14 | 0/0/0 |  | grim2d-quad-xy-wrapper |
| match | grim_draw_quad_rotated_matrix | 0x10008750 | 953 | 236/236 | 100.00% | 236/236 | 81/0/0 |  | grim2d-matrix-quad |
| match | grim_draw_quad | 0x10008b10 | 800 | 195/195 | 100.00% | 195/195 | 68/0/0 |  | grim2d-quad-batching |
| match | grim_submit_vertex_raw | 0x10008e30 | 116 | 35/35 | 100.00% | 35/35 | 9/0/0 |  | grim2d-raw-vertex-submit |
| match | grim_submit_quad_raw | 0x10008eb0 | 91 | 25/25 | 100.00% | 25/25 | 7/0/0 |  | grim2d-raw-quad-submit |
| match | grim_draw_rect_outline | 0x10008f10 | 356 | 125/125 | 100.00% | 125/125 | 8/0/0 |  | grim2d-outlined-rectangle |
| match | grim_draw_quad_points | 0x10009080 | 554 | 130/130 | 100.00% | 130/130 | 59/0/0 |  | grim2d-quad-points |
| wip | grim_draw_text_mono | 0x100092b0 | 1034 | 298/308 | 94.39% | 6/308 | 41/0/0 |  | grim2d-mono-font-draw |
| match | grim_measure_text_width | 0x100096c0 | 98 | 45/45 | 100.00% | 45/45 | 2/0/0 |  | grim2d-small-font-measurement |
| match | grim_draw_text_small | 0x10009730 | 515 | 153/153 | 100.00% | 153/153 | 18/0/0 |  | grim2d-small-font-draw |
| match | grim_draw_text_mono_fmt | 0x10009940 | 52 | 16/16 | 100.00% | 16/16 | 3/0/0 |  | grim2d-mono-text-format-wrapper |
| match | grim_draw_text_small_fmt | 0x10009980 | 52 | 16/16 | 100.00% | 16/16 | 3/0/0 |  | grim2d-small-text-format-wrapper |
| match | GRIM__GetInterface | 0x100099c0 | 95 | 28/28 | 100.00% | 28/28 | 11/0/0 |  | grim-interface-factory |
| match | DllMain | 0x10009a20 | 38 | 10/10 | 100.00% | 10/10 | 3/0/0 |  | grim-dll-process-attach |
| match | grim_joystick_enum_device | 0x1000a110 | 50 | 16/16 | 100.00% | 16/16 | 3/0/0 |  | grim-joystick-enumeration |
| match | grim_joystick_configure_axis | 0x1000a150 | 99 | 26/26 | 100.00% | 26/26 | 1/0/0 |  | grim-joystick-axis-range |
| match | grim_joystick_init | 0x1000a1c0 | 231 | 90/90 | 100.00% | 90/90 | 19/0/0 |  | grim-joystick-init |
| match | grim_joystick_poll | 0x1000a2b0 | 87 | 32/32 | 100.00% | 32/32 | 5/0/0 |  | grim-joystick-poll |
| match | grim_joystick_button_down | 0x1000a310 | 19 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | grim-joystick-button-state |
| match | grim_joystick_shutdown | 0x1000a330 | 62 | 19/19 | 100.00% | 19/19 | 5/0/0 |  | grim-joystick-shutdown |
| match | grim_keyboard_key_down | 0x1000a370 | 19 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | grim-keyboard-state |
| match | grim_keyboard_init | 0x1000a390 | 272 | 89/89 | 100.00% | 89/89 | 18/0/0 |  | grim-keyboard-init |
| match | grim_keyboard_poll | 0x1000a4a0 | 165 | 60/60 | 100.00% | 60/60 | 9/0/0 |  | grim-keyboard-poll |
| match | grim_keyboard_shutdown | 0x1000a550 | 62 | 19/19 | 100.00% | 19/19 | 5/0/0 |  | grim-keyboard-shutdown |
| match | grim_mouse_button_down | 0x1000a590 | 14 | 4/4 | 100.00% | 4/4 | 1/0/0 |  | grim-mouse-button-state |
| match | grim_mouse_init | 0x1000a5a0 | 194 | 71/71 | 100.00% | 71/71 | 18/0/0 |  | grim-mouse-init |
| match | grim_mouse_poll | 0x1000a670 | 351 | 90/90 | 100.00% | 90/90 | 42/0/0 |  | grim-mouse-poll |
| match | grim_mouse_shutdown | 0x1000a7d0 | 62 | 19/19 | 100.00% | 19/19 | 5/0/0 |  | grim-mouse-shutdown |
