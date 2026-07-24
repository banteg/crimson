# Matching Status

Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.

**718/2173** functions matched, **134067/676681** code bytes (**19.8%**). Byte totals are manifest function extents with terminal padding trimmed.

## Images

| image | functions | bytes | code | scratches |
|---|---:|---:|---:|---:|
| crimsonland.exe | 501/997 | 107380/386756 | 27.8% | 501/621 |
| grim.dll | 217/1176 | 26687/289925 | 9.2% | 217/225 |

## crimsonland.exe

**501/997** functions, **107380/386756** bytes (**27.8%**), **501/621** scratches verified.

| state | function | address | bytes | insns | match | prefix | refs ok/?/! | build | note |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| match | console_input_clear | 0x00401030 | 18 | 5/5 | 100.00% | 5/5 | 3/0/0 |  | smoke |
| match | console_input_buffer | 0x00401050 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | console_input_poll | 0x00401060 | 139 | 41/41 | 100.00% | 41/41 | 15/0/0 |  | console-input-buffer-policy |
| match | invoke_callback_n | 0x004010f0 | 42 | 21/21 | 100.00% | 21/21 | 0/0/0 |  | member-callback-array-iterator |
| match | console_cmd_arg_get | 0x00401120 | 36 | 12/12 | 100.00% | 12/12 | 3/0/0 |  | console-command-arguments |
| match | console_cmd_argc_get | 0x00401150 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | console_global_construct_and_register | 0x00401160 | 10 | 2/2 | 100.00% | 2/2 | 2/0/0 |  | console-global-lifetime-registration |
| match | console_global_init | 0x00401170 | 10 | 2/2 | 100.00% | 2/2 | 2/0/0 |  | console-global-constructor-thunk |
| match | console_register_global_destructor_atexit | 0x00401180 | 12 | 4/4 | 100.00% | 4/4 | 2/0/0 |  | console-global-destructor-registration |
| match | console_global_destroy | 0x00401190 | 10 | 2/2 | 100.00% | 2/2 | 2/0/0 |  | console-global-destructor-thunk |
| match | console_clear_log | 0x004011a0 | 78 | 28/28 | 100.00% | 28/28 | 7/0/0 |  | console-log-clear |
| match | console_log_node_free | 0x004011f0 | 68 | 24/24 | 100.00% | 24/24 | 2/0/0 |  | console-log-node-destructor |
| match | console_cmd_quit | 0x00401240 | 8 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | console-quit-command |
| match | console_cmd_exec | 0x00401250 | 236 | 72/72 | 100.00% | 72/72 | 28/0/0 |  | console-script-execution |
| match | console_cmd_extend | 0x00401340 | 17 | 4/4 | 100.00% | 4/4 | 3/0/0 |  | console-height-extend |
| match | console_cmd_minimize | 0x00401360 | 11 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | console-minimize-command |
| match | console_cmdlist | 0x00401370 | 65 | 24/24 | 100.00% | 24/24 | 7/0/0 |  | console-command-list |
| match | console_vars | 0x004013c0 | 65 | 24/24 | 100.00% | 24/24 | 7/0/0 |  | console-cvar-list |
| match | console_echo | 0x00401410 | 245 | 93/93 | 100.00% | 93/93 | 17/0/0 |  | console-echo-command |
| match | console_cmd_set | 0x00401510 | 77 | 22/22 | 100.00% | 22/22 | 11/0/0 |  | console-cvar-set-command |
| match | console_init | 0x00401560 | 382 | 107/107 | 100.00% | 107/107 | 44/0/0 |  | console-queue-constructor |
| match | console_destroy | 0x004016e0 | 187 | 77/77 | 100.00% | 77/77 | 10/0/0 |  | console-owned-list-destruction |
| match | console_push_line | 0x004017a0 | 193 | 68/68 | 100.00% | 68/68 | 5/0/0 |  | console-log-insertion-and-eviction |
| match | console_printf | 0x00401870 | 49 | 17/17 | 100.00% | 17/17 | 4/0/0 |  | console-formatted-output |
| match | console_set_open | 0x004018b0 | 26 | 7/7 | 100.00% | 7/7 | 2/0/0 |  | console-open-state |
| match | console_history_apply | 0x004018d0 | 99 | 42/42 | 100.00% | 42/42 | 4/0/0 |  | console-history-navigation |
| match | console_exec_line | 0x00401940 | 254 | 90/90 | 100.00% | 90/90 | 19/0/0 |  | console-command-dispatch |
| wip | console_update | 0x00401a40 | 904 | 296/296 | 89.19% | 6/296 | 63/0/0 |  | console-input-history-and-animation-update |
| wip | console_render | 0x00401dd0 | 1408 | 400/400 | 99.50% | 23/400 | 61/0/0 |  | console-background-log-input-and-caret-rendering |
| match | console_register_cvar | 0x00402350 | 295 | 118/118 | 100.00% | 118/118 | 12/0/0 |  | console-cvar-registration |
| match | console_cvar_find | 0x00402480 | 92 | 47/47 | 100.00% | 47/47 | 0/0/0 |  | console-cvar-lookup |
| match | console_cvar_unregister | 0x004024e0 | 72 | 32/32 | 100.00% | 32/32 | 1/0/0 |  | console-cvar-unlink |
| match | console_command_unregister | 0x00402530 | 74 | 32/32 | 100.00% | 32/32 | 1/0/0 |  | console-command-unlink |
| match | console_tokenize_line | 0x00402580 | 161 | 55/55 | 100.00% | 55/55 | 10/0/0 |  | console-command-tokenization |
| match | console_cvar_autocomplete | 0x00402630 | 164 | 83/83 | 100.00% | 83/83 | 1/0/0 |  | console-cvar-autocomplete |
| match | console_register_command | 0x004026e0 | 99 | 38/38 | 100.00% | 38/38 | 2/0/0 |  | console-command-register |
| match | console_command_find | 0x00402750 | 93 | 47/47 | 100.00% | 47/47 | 0/0/0 |  | console-command-lookup |
| match | console_command_autocomplete | 0x004027b0 | 165 | 83/83 | 100.00% | 83/83 | 1/0/0 |  | console-command-autocomplete |
| match | console_flush_log | 0x00402860 | 121 | 56/56 | 100.00% | 56/56 | 6/0/0 |  | console-log-file-flush |
| match | j_config_init_defaults | 0x004028e0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | tail-thunk-to-config-defaults |
| wip | config_init_defaults | 0x004028f0 | 734 | 143/140 | 77.74% | 0/140 | 65/0/2 |  | config-defaults-and-input-bindings |
| match | game_build_path | 0x00402bd0 | 34 | 9/9 | 100.00% | 9/9 | 5/0/0 |  | game-path-builder |
| match | register_core_cvars | 0x00402c00 | 326 | 66/66 | 100.00% | 66/66 | 65/0/0 |  | core-console-variable-registration |
| match | ui_render_loading | 0x00402d50 | 375 | 107/107 | 100.00% | 107/107 | 15/0/0 |  | ui-loading-panel-renderer |
| match | demo_setup_variant_0 | 0x00402ed0 | 263 | 70/70 | 100.00% | 70/70 | 10/0/0 |  | demo-spider-corridor-setup |
| match | demo_setup_variant_2 | 0x00402fe0 | 271 | 81/81 | 100.00% | 81/81 | 7/0/0 |  | demo-zombie-column-setup |
| match | demo_setup_variant_1 | 0x004030f0 | 338 | 88/88 | 100.00% | 88/88 | 17/0/0 |  | demo-green-spider-setup |
| match | demo_setup_variant_3 | 0x00403250 | 278 | 78/78 | 100.00% | 78/78 | 13/0/0 |  | demo-green-alien-setup |
| match | demo_purchase_interstitial_begin | 0x00403370 | 18 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | demo-purchase-interstitial |
| match | demo_mode_start | 0x00403390 | 155 | 40/40 | 100.00% | 40/40 | 17/0/0 |  | demo-attract-mode-cycle |
| match | ui_mouse_inside_rect_with_padding | 0x00403430 | 104 | 32/32 | 100.00% | 32/32 | 7/0/0 |  | ui-mouse-hit-test |
| match | ui_mouse_inside_rect | 0x004034a0 | 92 | 30/30 | 100.00% | 30/30 | 5/0/0 |  | ui-mouse-hit-test |
| match | game_core_init | 0x00403500 | 73 | 17/17 | 100.00% | 17/17 | 12/0/0 |  | game-core-initialization |
| match | perk_prompt_update_and_render | 0x00403550 | 378 | 93/93 | 100.00% | 93/93 | 35/0/0 |  | ui-perk-prompt-animation |
| match | input_key_name | 0x004036d0 | 2970 | 1097/1097 | 100.00% | 1097/1097 | 256/0/0 |  | input-device-key-label-policy |
| match | perks_generate_choices | 0x004045a0 | 535 | 139/139 | 100.00% | 139/139 | 54/0/0 |  | perk-choice-generation-policy |
| wip | demo_trial_overlay_render | 0x004047c0 | 2413 | 616/636 | 94.25% | 205/636 | 171/0/0 |  | demo-trial-overlay-render-and-actions |
| match | demo_trial_already_paid_button_destroy | 0x00405130 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | demo-overlay-already-paid-button-empty-destructor |
| match | demo_trial_purchase_button_destroy | 0x00405140 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | demo-overlay-purchase-button-empty-destructor |
| match | demo_trial_maybe_later_button_destroy | 0x00405150 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | demo-overlay-maybe-later-button-empty-destructor |
| match | ui_render_keybind_help | 0x00405160 | 1142 | 324/324 | 100.00% | 324/324 | 80/0/0 |  | pause-keybind-help-panel |
| wip | perk_apply | 0x004055e0 | 885 | 241/241 | 63.07% | 2/241 | 63/0/0 |  | perk-immediate-effect-dispatch |
| match | gameplay_render_world | 0x00405960 | 625 | 184/184 | 100.00% | 184/184 | 56/0/0 |  | gameplay-world-render-coordinator |
| wip | perk_selection_screen_update | 0x00405be0 | 1347 | 314/314 | 86.94% | 0/314 | 117/0/0 |  | perk-choice-menu-and-selection-flow |
| match | perk_selection_select_button_destroy | 0x00406130 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | perk-selection-select-button-empty-destructor |
| match | perk_selection_cancel_button_destroy | 0x00406140 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | perk-selection-cancel-button-empty-destructor |
| match | perk_selection_choice_items_destroy | 0x00406150 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | perk-selection-choice-array-empty-destructor |
| match | perk_selection_hover_color_destroy | 0x00406160 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | perk-selection-hover-color-empty-destructor |
| match | perk_selection_idle_color_destroy | 0x00406170 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | perk-selection-idle-color-empty-destructor |
| match | format_ordinal | 0x00406180 | 96 | 33/33 | 100.00% | 33/33 | 8/0/0 |  | ui-ordinal-format |
| match | ui_draw_clock_gauge | 0x004061e0 | 362 | 99/99 | 100.00% | 99/99 | 17/0/0 |  | ui-clock-gauge-renderer |
| match | game_update_victory_screen | 0x00406350 | 1883 | 447/447 | 100.00% | 447/447 | 189/0/0 |  | final-quest-victory-message-and-mode-actions |
| match | game_completed_main_menu_button_destroy | 0x00406ab0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | victory-main-menu-button-empty-destructor |
| match | game_completed_typo_button_destroy | 0x00406ac0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | victory-typo-button-empty-destructor |
| match | game_completed_rush_button_destroy | 0x00406ad0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | victory-rush-button-empty-destructor |
| match | game_completed_survival_button_destroy | 0x00406ae0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | victory-survival-button-empty-destructor |
| match | game_update_generic_menu | 0x00406af0 | 72 | 19/19 | 100.00% | 19/19 | 9/0/0 |  | generic-menu-render-coordinator |
| match | perks_update_effects | 0x00406b40 | 1437 | 352/352 | 100.00% | 352/352 | 136/0/0 |  | perk-runtime-effects |
| match | quest_mode_update | 0x004070e0 | 455 | 108/108 | 100.00% | 108/108 | 52/0/0 |  | quest-completion-transition-coordinator |
| match | rush_mode_update | 0x004072b0 | 594 | 136/136 | 100.00% | 136/136 | 51/0/0 |  | rush-mode-edge-wave-spawn-update |
| match | survival_spawn_creature | 0x00407510 | 1973 | 517/517 | 100.00% | 517/517 | 85/0/0 |  | survival-random-creature-stats-and-rare-variants |
| wip | survival_update | 0x00407cd0 | 2102 | 504/504 | 98.21% | 102/504 | 139/0/0 |  | survival-handouts-milestones-and-edge-wave-spawns |
| match | tutorial_prompt_dialog | 0x00408530 | 1084 | 254/254 | 100.00% | 254/254 | 80/0/0 |  | tutorial-prompt-actions |
| wip | tutorial_timeline_update | 0x00408990 | 2907 | 701/695 | 63.75% | 6/695 | 153/0/4 |  | tutorial-script-prompts-hints-and-spawns |
| match | camera_update | 0x00409500 | 910 | 249/249 | 100.00% | 249/249 | 76/0/0 |  | camera-shake-focus-and-clamp |
| match | bonus_apply | 0x00409890 | 2693 | 668/668 | 100.00% | 668/668 | 216/0/0 |  | gameplay-bonus-switch |
| match | bonus_update | 0x0040a320 | 416 | 115/115 | 100.00% | 115/115 | 37/0/0 |  | gameplay-bonus-update |
| match | ui_draw_clock_gauge_at | 0x0040a4c0 | 70 | 22/22 | 100.00% | 22/22 | 6/0/0 |  | ui-clock-gauge-wrapper |
| match | ui_render_aim_indicators | 0x0040a510 | 1402 | 343/343 | 100.00% | 343/343 | 105/0/0 |  | ui-aim-reload-and-direction-indicators |
| match | ui_render_aim_lifetime_destroy | 0x0040aa90 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | ui-aim-second-static-empty-destructor |
| match | ui_render_aim_screen_destroy | 0x0040aaa0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | ui-aim-screen-vector-empty-destructor |
| match | gameplay_update_and_render | 0x0040aab0 | 2840 | 713/713 | 100.00% | 713/713 | 291/0/0 |  | core-gameplay-frame-coordinator |
| match | plugin_runtime_clear_pools | 0x0040b5d0 | 89 | 24/24 | 100.00% | 24/24 | 8/0/0 |  | plugin-runtime-pool-reset |
| match | plugin_runtime_update_and_render | 0x0040b630 | 265 | 67/67 | 100.00% | 67/67 | 33/0/0 |  | plugin-runtime-frame-lifecycle |
| wip | demo_purchase_screen_update | 0x0040b740 | 2642 | 697/691 | 88.18% | 1/691 | 187/0/0 |  | demo-purchase-screen-complete-flow |
| match | demo_purchase_purchase_button_destroy | 0x0040c1a0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | demo-purchase-purchase-button-empty-destructor |
| match | demo_purchase_maybe_later_button_destroy | 0x0040c1b0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | demo-purchase-maybe-later-button-empty-destructor |
| wip | game_frame_update | 0x0040c1c0 | 3588 | 903/905 | 93.92% | 363/905 | 314/0/0 |  | core-frame-timing-input-and-state-dispatch |
| match | credits_line_table_global_init_thunk | 0x0040cfd0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | credits-line-table-global-initialization-thunk |
| match | credits_line_table_global_init | 0x0040cfe0 | 24 | 9/9 | 100.00% | 9/9 | 1/0/0 |  | credits-line-table-global-initialization |
| match | credits_line_set | 0x0040d000 | 64 | 18/18 | 100.00% | 18/18 | 6/0/0 |  | credits-line-storage |
| match | credits_line_clear_flag | 0x0040d040 | 66 | 20/20 | 100.00% | 20/20 | 5/0/0 |  | credits-secret-penalty |
| match | credits_build_lines | 0x0040d090 | 1897 | 544/544 | 100.00% | 544/544 | 261/0/0 |  | credits-line-table-population |
| wip | credits_screen_update | 0x0040d800 | 1857 | 454/454 | 98.90% | 48/454 | 175/0/0 |  | credits-scroll-and-secret-puzzle |
| match | credits_secret_button_destroy | 0x0040df50 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | credits-secret-button-empty-destructor |
| match | credits_back_button_destroy | 0x0040df60 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | credits-back-button-empty-destructor |
| match | j_mod_api_init | 0x0040df90 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | tail-thunk-to-mod-api-init |
| match | mod_api_init | 0x0040dfa0 | 21 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | mod-api-global-constructor |
| match | mod_api_core_printf | 0x0040dfc0 | 52 | 14/14 | 100.00% | 14/14 | 7/0/0 |  | mod-api-core-console-output |
| match | mod_api_debug_printf | 0x0040e000 | 50 | 14/14 | 100.00% | 14/14 | 2/0/0 |  | mod-api-debug-output |
| match | mod_api_core_get_var | 0x0040e040 | 61 | 21/21 | 100.00% | 21/21 | 5/0/0 |  | mod-api-core-cvar-view |
| match | mod_api_core_del_var | 0x0040e080 | 18 | 5/5 | 100.00% | 5/5 | 2/0/0 |  | mod-api-core-cvar-delete |
| match | mod_api_core_execute | 0x0040e0a0 | 18 | 5/5 | 100.00% | 5/5 | 2/0/0 |  | mod-api-core-console-execute |
| match | mod_api_core_add_command | 0x0040e0c0 | 23 | 7/7 | 100.00% | 7/7 | 2/0/0 |  | mod-api-core-command-register |
| match | mod_api_core_del_command | 0x0040e0e0 | 18 | 5/5 | 100.00% | 5/5 | 2/0/0 |  | mod-api-core-command-delete |
| match | mod_api_core_get_extension | 0x0040e100 | 233 | 101/101 | 100.00% | 101/101 | 5/0/0 |  | mod-api-core-extension-query |
| match | mod_api_gfx_clear | 0x0040e1f0 | 34 | 12/12 | 100.00% | 12/12 | 1/0/0 |  | mod-api-graphics-clear |
| match | mod_api_gfx_get_string_width | 0x0040e220 | 22 | 6/6 | 100.00% | 6/6 | 1/0/0 |  | mod-api-graphics-text-width |
| match | mod_api_gfx_printf | 0x0040e240 | 53 | 16/16 | 100.00% | 16/16 | 4/0/0 |  | mod-api-graphics-formatted-text |
| match | mod_api_gfx_load_texture | 0x0040e280 | 83 | 23/23 | 100.00% | 23/23 | 5/0/0 |  | mod-api-graphics-texture-load |
| match | mod_api_gfx_free_texture | 0x0040e2e0 | 24 | 7/7 | 100.00% | 7/7 | 1/0/0 |  | mod-api-graphics-texture-free |
| match | mod_api_gfx_set_texture | 0x0040e300 | 24 | 7/7 | 100.00% | 7/7 | 1/0/0 |  | mod-api-graphics-texture-bind |
| match | mod_api_gfx_set_color | 0x0040e320 | 37 | 12/12 | 100.00% | 12/12 | 1/0/0 |  | mod-api-graphics-color |
| match | mod_api_gfx_set_subset | 0x0040e350 | 37 | 12/12 | 100.00% | 12/12 | 1/0/0 |  | mod-api-graphics-uv-subset |
| match | mod_api_gfx_set_texture_filter | 0x0040e380 | 27 | 9/9 | 100.00% | 9/9 | 1/0/0 |  | mod-api-graphics-texture-filter |
| match | mod_api_gfx_set_blend_mode | 0x0040e3a0 | 51 | 17/17 | 100.00% | 17/17 | 2/0/0 |  | mod-api-graphics-blend-mode |
| match | mod_api_gfx_begin | 0x0040e3e0 | 22 | 5/5 | 100.00% | 5/5 | 2/0/0 |  | mod-api-graphics-batch |
| match | mod_api_gfx_end | 0x0040e400 | 22 | 5/5 | 100.00% | 5/5 | 2/0/0 |  | mod-api-graphics-batch |
| match | mod_api_gfx_quad | 0x0040e420 | 76 | 22/22 | 100.00% | 22/22 | 4/0/0 |  | mod-api-graphics-quad |
| match | mod_api_gfx_quad_rot | 0x0040e470 | 79 | 23/23 | 100.00% | 23/23 | 4/0/0 |  | mod-api-graphics-rotated-quad |
| match | mod_api_gfx_draw_quads | 0x0040e4c0 | 100 | 26/26 | 100.00% | 26/26 | 5/0/0 |  | mod-api-graphics-quad-batch |
| match | mod_api_sfx_load_sample | 0x0040e530 | 45 | 12/12 | 100.00% | 12/12 | 3/0/0 |  | mod-api-audio-sample-load |
| match | mod_api_sfx_free_sample | 0x0040e560 | 16 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | mod-api-audio-sample-release |
| match | mod_api_sfx_play_sample | 0x0040e570 | 51 | 14/14 | 100.00% | 14/14 | 2/0/0 |  | mod-api-audio-sample-play |
| match | mod_api_sfx_load_tune | 0x0040e5b0 | 45 | 12/12 | 100.00% | 12/12 | 3/0/0 |  | mod-api-audio-tune-load |
| match | mod_api_sfx_free_tune | 0x0040e5e0 | 16 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | mod-api-audio-tune-release |
| match | mod_api_sfx_play_tune | 0x0040e5f0 | 14 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | mod-api-audio-tune-play |
| match | mod_api_sfx_stop_tune | 0x0040e600 | 14 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | mod-api-audio-tune-stop |
| match | mod_api_inp_get_pressed_char | 0x0040e610 | 11 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | mod-api-input-character |
| match | mod_api_inp_get_analog | 0x0040e620 | 54 | 14/14 | 100.00% | 14/14 | 3/0/0 |  | mod-api-input-analog |
| match | mod_api_inp_key_down | 0x0040e660 | 32 | 10/10 | 100.00% | 10/10 | 1/0/0 |  | mod-api-input-key-state |
| match | mod_api_inp_get_key_name | 0x0040e680 | 16 | 5/5 | 100.00% | 5/5 | 1/0/0 |  | mod-api-input-key-name |
| match | mod_api_cl_enter_menu | 0x0040e690 | 99 | 37/37 | 100.00% | 37/37 | 4/0/0 |  | mod-api-pause-menu |
| match | mod_load_info | 0x0040e700 | 332 | 91/91 | 100.00% | 91/91 | 36/0/0 |  | mod-metadata-dll-loader |
| match | mod_load_mod | 0x0040e860 | 219 | 61/61 | 100.00% | 61/61 | 24/0/0 |  | mod-interface-dll-loader |
| match | mods_any_available | 0x0040e940 | 87 | 33/33 | 100.00% | 33/33 | 4/0/0 |  | mods-dll-presence |
| wip | mods_menu_update | 0x0040e9a0 | 2607 | 645/648 | 83.06% | 0/648 | 166/0/1 |  | mods-browser-metadata-and-plugin-launch |
| match | mods_menu_launch_button_destroy | 0x0040f3d0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | mods-menu-launch-button-empty-destructor |
| match | mods_menu_main_menu_button_destroy | 0x0040f3e0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | mods-menu-main-menu-button-empty-destructor |
| match | mods_menu_scrollbar_destroy | 0x0040f3f0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | mods-menu-scrollbar-empty-destructor |
| match | credits_secret_match3_find | 0x0040f400 | 230 | 96/96 | 100.00% | 96/96 | 0/0/0 |  | credits-secret-match3-scan |
| wip | credits_secret_alien_zookeeper_update | 0x0040f4f0 | 2612 | 638/638 | 83.70% | 15/638 | 153/0/0 |  | credits-secret-match3-board-timer-scoring-and-navigation |
| match | time_format_mm_ss | 0x0040ff50 | 105 | 37/37 | 100.00% | 37/37 | 8/0/0 |  | ui-time-format |
| match | game_over_screen_update | 0x0040ffc0 | 1999 | 471/471 | 100.00% | 471/471 | 215/0/0 |  | game-over-highscore-entry-and-navigation |
| match | game_over_main_menu_button_destroy | 0x00410790 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | game-over-main-menu-button-empty-destructor |
| match | game_over_highscores_button_destroy | 0x004107a0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | game-over-highscores-button-empty-destructor |
| match | game_over_play_again_button_destroy | 0x004107b0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | game-over-play-again-button-empty-destructor |
| match | game_over_name_input_state_destroy | 0x004107c0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | game-over-name-input-empty-destructor |
| match | game_over_name_submit_button_destroy | 0x004107d0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | game-over-name-submit-button-empty-destructor |
| wip | quest_failed_screen_update | 0x004107e0 | 1261 | 292/292 | 99.32% | 30/292 | 151/0/0 |  | quest-failed-highscore-and-retry-actions |
| match | quest_failed_main_menu_button_destroy | 0x00410cf0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-failed-main-menu-button-empty-destructor |
| match | quest_failed_play_another_button_destroy | 0x00410d00 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-failed-play-another-button-empty-destructor |
| match | quest_failed_play_again_button_destroy | 0x00410d10 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-failed-play-again-button-empty-destructor |
| wip | quest_results_screen_update | 0x00410d20 | 4857 | 1164/1168 | 85.59% | 1/1168 | 424/0/9 |  | quest-time-breakdown-highscore-entry-unlocks-and-routing |
| match | quest_results_main_menu_button_destroy | 0x00412020 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-results-main-menu-button-empty-destructor |
| match | quest_results_highscores_button_destroy | 0x00412030 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-results-highscores-button-empty-destructor |
| match | quest_results_play_again_button_destroy | 0x00412040 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-results-play-again-button-empty-destructor |
| match | quest_results_play_next_button_destroy | 0x00412050 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-results-play-next-button-empty-destructor |
| match | quest_results_name_input_state_destroy | 0x00412060 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-results-name-input-empty-destructor |
| match | quest_results_name_submit_button_destroy | 0x00412070 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-results-name-submit-button-empty-destructor |
| match | j_gameplay_run_state_init | 0x004120a0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | tail-thunk-to-gameplay-run-state-init |
| match | gameplay_run_state_init | 0x004120b0 | 172 | 44/44 | 100.00% | 44/44 | 20/0/0 |  | gameplay-run-initialization |
| match | quest_meta_global_construct_and_register | 0x00412180 | 10 | 2/2 | 100.00% | 2/2 | 2/0/0 |  | quest-metadata-global-lifecycle |
| match | quest_meta_init | 0x00412190 | 25 | 7/7 | 100.00% | 7/7 | 4/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | quest-metadata-array-construction |
| match | quest_meta_entry_init | 0x004121b0 | 45 | 13/13 | 100.00% | 13/13 | 0/0/0 |  | quest-metadata-entry-defaults |
| match | quest_meta_entry_release | 0x004121e0 | 15 | 7/7 | 100.00% | 7/7 | 1/0/0 |  | quest-metadata-owned-name-release |
| match | quest_meta_register_atexit | 0x004121f0 | 12 | 4/4 | 100.00% | 4/4 | 2/0/0 |  | quest-metadata-destructor-registration |
| match | quest_meta_table_destroy | 0x00412200 | 20 | 6/6 | 100.00% | 6/6 | 3/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | quest-metadata-array-destruction |
| match | bonus_pool_global_init_thunk | 0x00412220 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | bonus-pool-global-initialization-thunk |
| match | bonus_pool_global_init | 0x00412230 | 23 | 7/7 | 100.00% | 7/7 | 1/0/0 |  | bonus-pool-global-initialization |
| match | creature_spawn_slot_table_global_init_thunk | 0x00412250 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | creature-spawn-slot-global-initialization-thunk |
| match | creature_spawn_slot_table_global_init | 0x00412260 | 45 | 12/12 | 100.00% | 12/12 | 1/0/0 |  | creature-spawn-slot-global-initialization |
| match | game_status_global_init_thunk | 0x00412290 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | game-status-global-init-thunk |
| match | game_status_global_init | 0x004122a0 | 171 | 45/45 | 100.00% | 45/45 | 18/0/0 |  | game-status-global-constructor |
| match | j_highscore_init_sentinels | 0x00412350 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | tail-thunk-to-highscore-sentinel-init |
| match | highscore_init_sentinels | 0x00412360 | 96 | 38/38 | 100.00% | 38/38 | 3/0/0 |  | highscore-sentinels |
| match | bonus_meta_global_construct_and_register | 0x004123c0 | 10 | 2/2 | 100.00% | 2/2 | 2/0/0 |  | bonus-metadata-global-lifecycle |
| match | bonus_meta_table_init | 0x004123d0 | 25 | 7/7 | 100.00% | 7/7 | 4/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | bonus-metadata-array-construction |
| match | bonus_meta_entry_init | 0x004123f0 | 27 | 8/8 | 100.00% | 8/8 | 0/0/0 |  | bonus-metadata-entry-defaults |
| match | bonus_meta_entry_release | 0x00412410 | 36 | 16/16 | 100.00% | 16/16 | 2/0/0 |  | metadata-owned-string-release |
| match | bonus_meta_register_atexit | 0x00412440 | 12 | 4/4 | 100.00% | 4/4 | 2/0/0 |  | bonus-metadata-destructor-registration |
| match | bonus_meta_table_destroy | 0x00412450 | 20 | 6/6 | 100.00% | 6/6 | 3/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | bonus-metadata-array-destruction |
| wip | bonus_pick_random_type | 0x00412470 | 484 | 162/162 | 75.93% | 55/162 | 20/0/0 |  | gameplay-bonus-selection |
| match | bonus_metadata_init | 0x00412660 | 735 | 131/131 | 100.00% | 131/131 | 109/0/0 |  | bonus-metadata-initialization |
| match | bonus_reset_availability | 0x00412940 | 26 | 7/7 | 100.00% | 7/7 | 3/0/0 |  | gameplay-bonus-availability-reset |
| wip | game_mode_label | 0x00412960 | 176 | 69/69 | 86.96% | 6/69 | 10/0/0 |  | game-mode-display-label |
| match | game_sequence_load | 0x00412a10 | 101 | 32/32 | 100.00% | 32/32 | 7/0/0 |  | status-sequence-registry-load |
| match | game_save_status | 0x00412a80 | 399 | 123/123 | 100.00% | 123/123 | 36/0/0 |  | game-status-save-transform |
| match | game_load_status | 0x00412c10 | 420 | 134/134 | 100.00% | 134/134 | 43/0/0 |  | game-status-load-transform |
| wip | gameplay_reset_state | 0x00412dc0 | 1639 | 307/307 | 99.02% | 165/307 | 213/0/0 |  | gameplay-session-state-reset |
| match | player_start_reload | 0x00413430 | 263 | 67/67 | 100.00% | 67/67 | 28/0/0 |  | gameplay-reload |
| match | player_heading_approach_target | 0x00413540 | 354 | 95/95 | 100.00% | 95/95 | 27/0/0 |  | gameplay-angle-x87 |
| wip | player_update | 0x004136b0 | 16257 | 3983/4206 | 52.22% | 7/4206 | 691/0/11 |  | core-player-simulation |
| match | vec2_sub | 0x00417640 | 26 | 9/9 | 100.00% | 9/9 | 0/0/0 |  | x87-vector-subtract |
| match | vec2_length | 0x00417660 | 26 | 12/12 | 100.00% | 12/12 | 0/0/0 |  | x87-fsqrt |
| match | j_ui_menu_template_pool_init | 0x00417680 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | tail-thunk-to-ui-template-init |
| match | ui_menu_template_pool_init | 0x00417690 | 336 | 92/92 | 100.00% | 92/92 | 42/0/0 |  | ui-template-pool-construction |
| match | ui_element_globals_init_thunk | 0x004177e0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | ui-element-global-init-thunk |
| match | ui_element_globals_init | 0x004177f0 | 662 | 135/135 | 100.00% | 135/135 | 121/0/0 |  | ui-element-global-construction |
| match | ui_template_slot_ctor_noop | 0x00417a90 | 3 | 2/2 | 100.00% | 2/2 | 0/0/0 |  | ui-template-trivial-slot-constructor |
| match | ui_template_block_set_mode4 | 0x00417aa0 | 13 | 3/3 | 100.00% | 3/3 | 0/0/0 |  | ui-subtemplate-mode-init |
| match | ui_template_triplet_reset_and_seed_modes | 0x00417ab0 | 48 | 12/12 | 100.00% | 12/12 | 0/0/0 |  | ui-template-triplet-init |
| match | ui_draw_textured_quad | 0x00417ae0 | 158 | 46/46 | 100.00% | 46/46 | 6/0/0 |  | ui-textured-quad |
| match | terrain_generate | 0x00417b80 | 1569 | 408/408 | 100.00% | 408/408 | 88/0/0 |  | terrain-render-target-scatter-generation |
| match | terrain_generate_random | 0x004181b0 | 1764 | 465/465 | 100.00% | 465/465 | 110/0/0 |  | random-terrain-selector-and-scatter-generation |
| match | terrain_render | 0x004188a0 | 693 | 200/200 | 100.00% | 200/200 | 32/0/0 |  | terrain-backbuffer-render |
| wip | creature_render_type | 0x00418b60 | 2834 | 757/765 | 78.45% | 25/765 | 136/0/5 |  | creature-atlas-animation-tint-and-lifecycle-rendering |
| match | creature_render_all | 0x00419680 | 1302 | 349/349 | 100.00% | 349/349 | 87/0/0 |  | creature-overlay-species-and-freeze-render-passes |
| wip | ui_element_set_rect | 0x00419ba0 | 348 | 92/91 | 43.72% | 0/91 | 4/0/0 |  | ui-subtemplate-quad-geometry |
| match | ui_element_load | 0x00419d00 | 207 | 67/67 | 100.00% | 67/67 | 10/0/0 |  | ui-element-texture-load |
| audit | ui_menu_assets_init | 0x00419dd0 | 551 | 110/110 | 100.00% | 110/110 | 64/0/2 |  | ui-menu-template-assets |
| wip | ui_cursor_render | 0x0041a040 | 730 | 177/177 | 98.87% | 158/177 | 57/0/0 |  | ui-cursor-particle-renderer |
| match | ui_render_aim_enhancement | 0x0041a320 | 518 | 131/131 | 100.00% | 131/131 | 35/0/0 |  | ui-aim-enhancement-overlay |
| match | ui_elements_update_and_render | 0x0041a530 | 409 | 103/103 | 100.00% | 103/103 | 41/0/0 |  | ui-transition-update-render |
| match | ui_draw_progress_bar | 0x0041a6d0 | 237 | 66/66 | 100.00% | 66/66 | 11/0/0 |  | ui-progress-bar |
| match | bonus_hud_slot_table_global_init_thunk | 0x0041a7c0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | bonus-hud-slot-table-global-init-thunk |
| match | bonus_hud_slot_table_global_init | 0x0041a7d0 | 56 | 13/13 | 100.00% | 13/13 | 2/0/0 |  | bonus-hud-slot-table-global-constructor |
| match | bonus_hud_slot_activate | 0x0041a810 | 159 | 54/54 | 100.00% | 54/54 | 8/0/0 |  | bonus-hud-slot-allocation |
| wip | bonus_hud_slot_update_and_render | 0x0041a8b0 | 1566 | 407/405 | 77.83% | 5/405 | 69/0/0 |  | bonus-hud-slot-animation-and-rendering |
| wip | ui_render_hud | 0x0041aed0 | 7081 | 1824/1824 | 84.59% | 42/1824 | 381/0/3 |  | gameplay-hud-health-ammo-quest-xp-and-bonus-overlay |
| match | ui_hud_progress_color_destroy | 0x0041ca80 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | ui-hud-static-progress-color-destructor |
| match | hud_update_and_render | 0x0041ca90 | 531 | 126/126 | 100.00% | 126/126 | 49/0/0 |  | gameplay-hud-coordinator |
| match | dx_get_version | 0x0041ccb0 | 251 | 106/106 | 100.00% | 106/106 | 7/0/0 |  | directx-version-query-and-format |
| match | dx_get_version_from_dxdiag | 0x0041cdb0 | 556 | 190/190 | 100.00% | 190/190 | 12/0/0 |  | directx-dxdiag-com-version-probe |
| match | win32_file_get_version_words | 0x0041db50 | 187 | 78/78 | 100.00% | 78/78 | 7/0/0 |  | win32-file-version-query |
| match | dx_version_pack_4x16 | 0x0041dc10 | 49 | 13/13 | 100.00% | 13/13 | 0/0/0 |  | directx-version-pack |
| match | dx_version_compare_4x16 | 0x0041dc50 | 45 | 17/17 | 100.00% | 17/17 | 0/0/0 |  | directx-version-compare |
| match | grim_load_interface | 0x0041dc80 | 83 | 36/36 | 100.00% | 36/36 | 5/0/0 |  | grim-interface-loader |
| match | vorbis_mem_read | 0x0041dce0 | 88 | 37/37 | 100.00% | 37/37 | 0/0/0 |  | vorbis-memory-read-callback |
| match | vorbis_mem_seek | 0x0041dd40 | 66 | 22/22 | 100.00% | 22/22 | 0/0/0 |  | vorbis-memory-seek-callback |
| match | vorbis_mem_close_callback | 0x0041dd90 | 6 | 2/2 | 100.00% | 2/2 | 0/0/0 |  | vorbis-memory-close-callback |
| match | vorbis_mem_tell | 0x0041dda0 | 8 | 3/3 | 100.00% | 3/3 | 0/0/0 |  | vorbis-memory-tell-callback |
| match | vorbis_pcm_seek | 0x0041ddb0 | 22 | 8/8 | 100.00% | 8/8 | 1/0/0 |  | vorbis-pcm-seek-wrapper |
| match | vorbis_mem_open | 0x0041ddd0 | 260 | 91/91 | 100.00% | 91/91 | 13/0/0 |  | vorbis-memory-stream-open |
| match | vorbis_mem_close | 0x0041dee0 | 29 | 11/11 | 100.00% | 11/11 | 2/0/0 |  | vorbis-memory-stream-close |
| match | vorbis_read_pcm16 | 0x0041df00 | 55 | 22/22 | 100.00% | 22/22 | 1/0/0 |  | vorbis-pcm16-decode |
| match | game_is_full_version | 0x0041df40 | 3 | 2/2 | 100.00% | 2/2 | 0/0/0 |  | full-version-constant |
| match | demo_trial_time_limit_ms | 0x0041df50 | 6 | 2/2 | 100.00% | 2/2 | 0/0/0 |  | demo-trial-duration |
| match | game_sequence_get | 0x0041df60 | 6 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | smoke |
| match | unused_fx_queue_random_prefix_color_global_init_thunk | 0x0041df70 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-fx-queue-prefix-color-constructor-thunk |
| match | unused_fx_queue_random_prefix_color_global_init | 0x0041df80 | 41 | 5/5 | 100.00% | 5/5 | 4/0/0 |  | unused-fx-queue-prefix-color-constructor |
| match | unused_fx_rotated_effect_id_prefix_color_global_init_thunk | 0x0041dfb0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-fx-rotated-effect-id-prefix-color-constructor-thunk |
| match | unused_fx_rotated_effect_id_prefix_color_global_init | 0x0041dfc0 | 41 | 5/5 | 100.00% | 5/5 | 4/0/0 |  | unused-fx-rotated-effect-id-prefix-color-constructor |
| match | unused_aim64_prefix_color_global_init_thunk | 0x0041dff0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-aim64-prefix-color-constructor-thunk |
| match | unused_aim64_prefix_color_global_init | 0x0041e000 | 41 | 5/5 | 100.00% | 5/5 | 4/0/0 |  | unused-aim64-prefix-color-constructor |
| match | unused_fx_rotated_scale_prefix_color_global_init_thunk | 0x0041e030 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-fx-rotated-scale-prefix-color-constructor-thunk |
| match | unused_fx_rotated_scale_prefix_color_global_init | 0x0041e040 | 41 | 5/5 | 100.00% | 5/5 | 4/0/0 |  | unused-fx-rotated-scale-prefix-color-constructor |
| match | render_tint_color_global_init_thunk | 0x0041e070 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | render-tint-color-global-init-thunk |
| match | render_tint_color_global_init | 0x0041e080 | 41 | 5/5 | 100.00% | 5/5 | 4/0/0 |  | render-tint-color-global-constructor |
| match | unused_global_noop_init_thunk | 0x0041e0b0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-global-empty-constructor-thunk |
| match | unused_global_noop_init | 0x0041e0c0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | unused-global-empty-constructor |
| match | unused_particle_pool_suffix_color_global_init_thunk | 0x0041e0d0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-particle-pool-suffix-color-constructor-thunk |
| match | unused_particle_pool_suffix_color_global_init | 0x0041e0e0 | 41 | 5/5 | 100.00% | 5/5 | 4/0/0 |  | unused-particle-pool-suffix-color-constructor |
| match | unused_effect_uv8_prefix_state_global_init_thunk | 0x0041e110 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-effect-prefix-default-state-thunk |
| match | unused_effect_uv8_prefix_state_global_init | 0x0041e120 | 28 | 6/6 | 100.00% | 6/6 | 4/0/0 |  | unused-effect-prefix-default-state |
| match | unused_effect_uv16_prefix_vec2_global_init_thunk | 0x0041e140 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-effect-uv16-prefix-vec2-thunk |
| match | unused_effect_uv16_prefix_vec2_global_init | 0x0041e150 | 21 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | unused-effect-uv16-prefix-vec2 |
| match | unused_effect_uv_strip16_prefix_vec2_global_init_thunk | 0x0041e170 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-effect-strip16-prefix-vec2-thunk |
| match | unused_effect_uv_strip16_prefix_vec2_global_init | 0x0041e180 | 21 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | unused-effect-strip16-prefix-vec2 |
| match | fx_queue_global_init_thunk | 0x0041e1a0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | fx-queue-global-init-thunk |
| match | fx_queue_global_init | 0x0041e1b0 | 147 | 42/42 | 100.00% | 42/42 | 1/0/0 |  | fx-queue-global-constructor |
| match | vec2_add | 0x0041e270 | 26 | 10/10 | 100.00% | 10/10 | 0/0/0 |  | x87-vector-add |
| match | player_apply_move_with_spawn_avoidance | 0x0041e290 | 356 | 131/131 | 100.00% | 131/131 | 8/0/0 |  | gameplay-movement |
| match | vec2_add_inplace | 0x0041e400 | 26 | 10/10 | 100.00% | 10/10 | 0/0/0 |  | x87-vector-add |
| match | unused_fx_queue_random_prefix_vec2_global_init_thunk | 0x0041e420 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | unused-random-fx-prefix-vec2-thunk |
| match | unused_fx_queue_random_prefix_vec2_global_init | 0x0041e430 | 21 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | unused-random-fx-prefix-vec2 |
| match | secondary_projectile_pool_global_init_thunk | 0x0041e450 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | secondary-projectile-pool-global-init-thunk |
| match | secondary_projectile_pool_global_init | 0x0041e460 | 41 | 12/12 | 100.00% | 12/12 | 1/0/0 |  | secondary-projectile-pool-global-constructor |
| match | sprite_effect_pool_global_init_thunk | 0x0041e490 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | sprite-effect-pool-global-init-thunk |
| match | sprite_effect_pool_global_init | 0x0041e4a0 | 97 | 30/30 | 100.00% | 30/30 | 1/0/0 |  | sprite-effect-pool-global-constructor |
| match | particle_pool_global_init_thunk | 0x0041e510 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | particle-pool-global-init-thunk |
| match | particle_pool_global_init | 0x0041e520 | 159 | 44/44 | 100.00% | 44/44 | 3/0/0 |  | particle-pool-global-constructor |
| match | player_state_table_global_init_thunk | 0x0041e5c0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | player-state-table-global-init-thunk |
| match | player_state_table_global_init | 0x0041e5d0 | 227 | 50/50 | 100.00% | 50/50 | 1/0/0 |  | player-state-table-global-constructor |
| match | creature_pool_global_init_thunk | 0x0041e6c0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | creature-pool-global-init-thunk |
| match | creature_pool_global_init | 0x0041e6d0 | 60 | 17/17 | 100.00% | 17/17 | 1/0/0 |  | creature-pool-global-constructor |
| match | projectile_pool_global_init_thunk | 0x0041e750 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | projectile-pool-global-init-thunk |
| match | projectile_pool_global_init | 0x0041e760 | 51 | 16/16 | 100.00% | 16/16 | 1/0/0 |  | projectile-pool-global-constructor |
| match | fx_queue_add | 0x0041e840 | 140 | 39/39 | 100.00% | 39/39 | 10/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-fx-queue |
| match | input_aim_pov_left_active | 0x0041e8d0 | 32 | 10/10 | 100.00% | 10/10 | 2/0/0 |  | input-aim-pov-left |
| match | input_aim_pov_right_active | 0x0041e8f0 | 32 | 10/10 | 100.00% | 10/10 | 2/0/0 |  | input-aim-pov-right |
| wip | creature_handle_death | 0x0041e910 | 834 | 202/204 | 84.73% | 5/204 | 80/0/1 |  | creature-death-side-effects |
| match | config_sync_from_grim | 0x0041ec60 | 1225 | 277/277 | 100.00% | 277/277 | 37/0/0 |  | grim-config-sync-and-legacy-migration |
| match | config_ensure_file | 0x0041f130 | 112 | 36/36 | 100.00% | 36/36 | 13/0/0 |  | config-file-bootstrap |
| wip | config_load_presets | 0x0041f1a0 | 653 | 178/178 | 88.20% | 67/178 | 50/0/3 |  | config-file-load-and-runtime-sync |
| wip | angle_approach | 0x0041f430 | 299 | 100/101 | 90.55% | 73/101 | 9/0/0 |  | gameplay-angle-x87 |
| match | bonus_pool_sentinel_global_init_thunk | 0x0041f560 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | bonus-pool-sentinel-global-initialization-thunk |
| match | bonus_pool_sentinel_global_init | 0x0041f570 | 11 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | bonus-pool-sentinel-global-initialization |
| match | bonus_alloc_slot | 0x0041f580 | 46 | 14/14 | 100.00% | 14/14 | 4/0/0 |  | gameplay-bonus-pool |
| match | bonus_spawn_at | 0x0041f5b0 | 479 | 128/128 | 100.00% | 128/128 | 28/0/0 |  | gameplay-bonus-spawn |
| wip | bonus_spawn_at_pos | 0x0041f790 | 309 | 100/99 | 88.44% | 0/99 | 14/0/0 |  | gameplay-bonus-spawn |
| wip | bonus_try_spawn_on_kill | 0x0041f8d0 | 730 | 201/207 | 88.24% | 6/207 | 47/0/0 |  | gameplay-bonus-drop |
| match | fx_spawn_sprite | 0x0041fbb0 | 175 | 48/48 | 100.00% | 48/48 | 16/0/0 |  | gameplay-sprite-effect-spawn |
| match | weapon_table_entry | 0x0041fc60 | 19 | 6/6 | 100.00% | 6/6 | 1/0/0 |  | gameplay-weapon-table |
| wip | player_reset_all | 0x0041fc80 | 584 | 130/127 | 91.83% | 94/127 | 57/0/1 | msvc6.5 /O2 /GB /W3 /GR- /TP | gameplay-player-reset |
| match | effect_uv_tables_init | 0x0041fed0 | 356 | 109/109 | 100.00% | 109/109 | 15/0/0 |  | gameplay-effect-atlas-uv-init |
| wip | creature_find_nearest | 0x00420040 | 225 | 90/89 | 91.62% | 27/89 | 5/0/0 |  | gameplay-target-search |
| match | fx_spawn_particle | 0x00420130 | 264 | 67/67 | 100.00% | 67/67 | 18/0/0 |  | gameplay-particle-spawn |
| match | fx_spawn_particle_slow | 0x00420240 | 274 | 67/67 | 100.00% | 67/67 | 19/0/0 |  | gameplay-particle-spawn |
| match | fx_spawn_secondary_projectile | 0x00420360 | 218 | 65/65 | 100.00% | 65/65 | 13/0/0 |  | gameplay-secondary-projectile |
| wip | projectile_spawn | 0x00420440 | 400 | 114/126 | 71.67% | 0/126 | 13/0/0 |  | gameplay-projectile |
| match | projectile_reset_pools | 0x004205d0 | 37 | 11/11 | 100.00% | 11/11 | 4/0/0 |  | gameplay-pool-reset |
| match | creatures_apply_radius_damage | 0x00420600 | 159 | 57/57 | 100.00% | 57/57 | 6/0/0 |  | gameplay-radius-damage |
| match | creature_find_in_radius | 0x004206a0 | 133 | 47/47 | 100.00% | 47/47 | 5/0/0 |  | gameplay-target-search |
| match | player_find_in_radius | 0x00420730 | 133 | 54/54 | 100.00% | 54/54 | 5/0/0 |  | gameplay-target-search |
| wip | creature_apply_damage | 0x004207c0 | 963 | 237/237 | 89.87% | 11/237 | 80/0/0 |  | creature-damage-and-lethal-effects |
| wip | projectile_update | 0x00420b90 | 8409 | 2137/2203 | 46.91% | 0/2203 | 336/0/29 |  | core-projectile-simulation |
| wip | projectile_render | 0x00422c70 | 12551 | 2839/3021 | 43.04% | 0/3021 | 325/0/28 |  | laser-primary-plasma-beam-plague-and-secondary-projectile-passes |
| match | plaguebearer_spread_infection | 0x00425d80 | 203 | 64/64 | 100.00% | 64/64 | 14/0/0 |  | gameplay-plaguebearer-spread |
| match | player_take_damage | 0x00425e50 | 969 | 267/267 | 100.00% | 267/267 | 73/0/0 |  | gameplay-player-damage |
| wip | creature_update_all | 0x00426220 | 5330 | 1290/1338 | 49.09% | 0/1338 | 207/0/4 |  | creature-ai-movement-attacks-and-corpse-lifecycle |
| match | fx_queue_add_random | 0x00427700 | 291 | 73/73 | 100.00% | 73/73 | 23/0/0 |  | gameplay-random-fx-queue |
| match | fx_queue_random_color_destroy | 0x00427830 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | fx-random-color-trivial-destructor |
| match | fx_queue_add_rotated | 0x00427840 | 210 | 55/55 | 100.00% | 55/55 | 18/0/0 |  | gameplay-rotated-fx-queue |
| match | fx_queue_render | 0x00427920 | 2076 | 543/543 | 100.00% | 543/543 | 162/0/0 |  | terrain-fx-and-corpse-render-passes |
| match | creature_alloc_slot | 0x00428140 | 145 | 39/39 | 100.00% | 39/39 | 14/0/0 |  |  |
| match | creature_reset_all | 0x004281e0 | 46 | 13/13 | 100.00% | 13/13 | 3/0/0 |  | gameplay-creature-reset |
| match | creatures_none_active | 0x00428210 | 40 | 12/12 | 100.00% | 12/12 | 4/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-creature-scan |
| wip | creature_spawn | 0x00428240 | 334 | 79/79 | 86.08% | 7/79 | 27/0/0 |  | gameplay-creature-spawn |
| wip | player_render_overlays | 0x00428390 | 4582 | 1141/1148 | 83.88% | 9/1148 | 326/0/0 |  | player-sprites-shield-flash-and-native-residual-target-trail |
| match | bonus_label_for_entry | 0x00429580 | 99 | 30/30 | 100.00% | 30/30 | 11/0/0 |  | gameplay-bonus-label |
| wip | bonus_render | 0x004295f0 | 4088 | 1091/1088 | 85.64% | 14/1088 | 212/0/12 |  | bonus-icons-telekinetic-pickup-and-effect-pool-rendering |
| match | audio_resume_all | 0x0042a5f0 | 54 | 14/14 | 100.00% | 14/14 | 7/0/0 |  | audio-suspend-resume |
| match | audio_suspend_all | 0x0042a630 | 52 | 14/14 | 100.00% | 14/14 | 7/0/0 |  | audio-suspend-resume |
| match | texture_get_or_load | 0x0042a670 | 133 | 44/44 | 100.00% | 44/44 | 11/0/0 |  | texture-cache-load |
| match | texture_get_or_load_alt | 0x0042a700 | 126 | 40/40 | 100.00% | 40/40 | 11/0/0 |  | texture-cache-load-legacy |
| match | console_cmd_load_texture | 0x0042a780 | 60 | 19/19 | 100.00% | 19/19 | 7/0/0 |  | console-texture-load-command |
| match | console_cmd_set_resource_paq | 0x0042a7c0 | 158 | 51/51 | 100.00% | 51/51 | 18/0/0 |  | console-resource-pack-command |
| match | console_cmd_tell_time_survived | 0x0042a860 | 37 | 9/9 | 100.00% | 9/9 | 6/0/0 |  | console-survival-time |
| match | console_cmd_open_url | 0x0042a890 | 151 | 43/43 | 100.00% | 43/43 | 14/0/0 |  | console-open-url-command |
| match | console_cmd_snd_freq_adjustment | 0x0042a930 | 58 | 16/16 | 100.00% | 16/16 | 8/0/0 |  | console-sound-frequency-toggle |
| match | console_cmd_generate_terrain | 0x0042a970 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | console-terrain-generation-command |
| match | reg_read_dword_default | 0x0042a980 | 58 | 23/23 | 100.00% | 23/23 | 1/0/0 |  | registry-dword-read |
| match | reg_write_dword | 0x0042a9c0 | 37 | 14/14 | 100.00% | 14/14 | 1/0/0 |  | registry-dword-write |
| match | init_audio_and_terrain | 0x0042a9f0 | 480 | 116/116 | 100.00% | 116/116 | 65/0/0 |  | audio-and-terrain-startup |
| match | load_textures_step | 0x0042abd0 | 1203 | 252/252 | 100.00% | 252/252 | 209/0/0 |  | startup-staged-texture-loading |
| match | game_startup_init_prelude | 0x0042b090 | 435 | 113/113 | 100.00% | 113/113 | 45/0/0 |  | startup-core-prelude |
| match | startup_audio_load_thread | 0x0042b250 | 63 | 14/14 | 100.00% | 14/14 | 11/0/0 |  | startup-audio-thread |
| wip | game_startup_init | 0x0042b290 | 4303 | 1123/1126 | 93.73% | 1/1126 | 325/0/3 |  | startup-loading-intro-and-frame-callback |
| match | console_cmd_snd_add_game_tune | 0x0042c360 | 100 | 29/29 | 100.00% | 29/29 | 9/0/0 |  | console-music-queue-command |
| match | console_cmd_set_gamma_ramp | 0x0042c3d0 | 116 | 35/35 | 100.00% | 35/35 | 13/0/0 |  | console-gamma-command |
| wip | highscore_sync_worker | 0x0042d0e0 | 1970 | 519/519 | 60.69% | 19/519 | 102/0/0 |  | online-highscore-submit-receive-worker |
| wip | statistics_update_check_worker | 0x0042d8a0 | 1364 | 371/361 | 69.95% | 21/361 | 101/1/0 |  | statistics-version-update-check-worker |
| match | effect_pool_vertices_global_init_thunk | 0x0042de00 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | effect-pool-vertex-global-init-thunk |
| match | effect_pool_vertices_global_init | 0x0042de10 | 39 | 15/15 | 100.00% | 15/15 | 3/0/0 |  | effect-pool-vertex-global-construction |
| match | effect_init_entry | 0x0042de80 | 143 | 36/36 | 100.00% | 36/36 | 0/0/0 |  | gameplay-effect-pool |
| match | effect_defaults_reset | 0x0042df10 | 355 | 59/59 | 100.00% | 59/59 | 29/0/0 |  | gameplay-effect-pool-reset |
| match | effect_free | 0x0042e080 | 29 | 6/6 | 100.00% | 6/6 | 2/0/0 |  | gameplay-effect-pool |
| match | effect_select_texture | 0x0042e0a0 | 113 | 35/35 | 100.00% | 35/35 | 6/0/0 |  | gameplay-effect-texture |
| match | effect_spawn | 0x0042e120 | 1507 | 350/350 | 100.00% | 350/350 | 90/0/0 |  | gameplay-effect-allocation-and-quad-build |
| match | effects_update | 0x0042e710 | 267 | 85/85 | 100.00% | 85/85 | 10/0/0 |  | gameplay-effect-lifecycle |
| wip | effects_render | 0x0042e820 | 740 | 195/195 | 92.82% | 37/195 | 38/0/0 |  | gameplay-effect-render-passes |
| match | effect_spawn_blood_splatter | 0x0042eb10 | 361 | 82/82 | 100.00% | 82/82 | 27/0/0 |  | gameplay-blood-splatter-effect |
| match | effect_spawn_freeze_shard | 0x0042ec80 | 376 | 81/81 | 100.00% | 81/81 | 33/0/0 |  | gameplay-freeze-shard-effect |
| match | effect_spawn_freeze_shatter | 0x0042ee00 | 339 | 79/79 | 100.00% | 79/79 | 27/0/0 |  | gameplay-freeze-shatter-effect |
| match | effect_spawn_burst | 0x0042ef60 | 282 | 61/61 | 100.00% | 61/61 | 21/0/0 |  | gameplay-effect-burst |
| match | effect_spawn_shrinkifier_hit | 0x0042f080 | 482 | 92/92 | 100.00% | 92/92 | 38/0/0 |  | gameplay-shrinkifier-impact |
| match | effect_spawn_ion_hit_core | 0x0042f270 | 191 | 32/32 | 100.00% | 32/32 | 16/0/0 |  | gameplay-effect-spawn |
| match | effect_spawn_plasma_hit_core | 0x0042f330 | 185 | 31/31 | 100.00% | 31/31 | 15/0/0 |  | gameplay-effect-spawn |
| match | effect_spawn_splitter_hit_burst | 0x0042f3f0 | 333 | 75/75 | 100.00% | 75/75 | 23/0/0 |  | gameplay-effect-spawn |
| match | effect_spawn_ion_hit_sparks | 0x0042f540 | 378 | 86/86 | 100.00% | 86/86 | 31/0/0 |  | gameplay-ion-hit-sparks |
| match | effect_spawn_explosion_burst | 0x0042f6c0 | 964 | 182/182 | 100.00% | 182/182 | 75/0/0 |  | gameplay-explosion-burst |
| match | perk_meta_global_construct_and_register | 0x0042fa90 | 10 | 2/2 | 100.00% | 2/2 | 2/0/0 |  | perk-metadata-global-lifecycle |
| match | perk_meta_table_init | 0x0042faa0 | 28 | 7/7 | 100.00% | 7/7 | 4/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | perk-metadata-array-construction |
| match | perk_meta_entry_init | 0x0042fac0 | 27 | 8/8 | 100.00% | 8/8 | 0/0/0 |  | perk-metadata-entry-defaults |
| match | perk_meta_register_atexit | 0x0042fae0 | 12 | 4/4 | 100.00% | 4/4 | 2/0/0 |  | perk-metadata-destructor-registration |
| match | perk_meta_table_destroy | 0x0042faf0 | 23 | 6/6 | 100.00% | 6/6 | 3/0/0 | msvc6.5 /O2 /GB /W3 /GR- /GX | perk-metadata-array-destruction |
| match | perk_can_offer | 0x0042fb10 | 185 | 55/55 | 100.00% | 55/55 | 17/0/0 |  | gameplay-perk-eligibility |
| match | perk_select_random | 0x0042fbd0 | 89 | 32/32 | 100.00% | 32/32 | 8/0/0 | msvc6.5pp /O2 /GB /W3 /GR- | gameplay-perk-rng |
| wip | perks_rebuild_available | 0x0042fc30 | 181 | 52/52 | 73.08% | 9/52 | 16/0/0 |  | gameplay-perk-unlocks |
| match | perk_count_get | 0x0042fcf0 | 12 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | gameplay-perk-count |
| wip | wrap_text_to_width_alloc | 0x0042fd00 | 143 | 60/62 | 81.97% | 0/62 | 2/0/0 |  | text-wrap-allocation |
| match | perks_init_database | 0x0042fd90 | 3211 | 588/588 | 100.00% | 588/588 | 443/0/0 |  | perk-id-and-metadata-database |
| match | quest_meta_init_entry | 0x00430a20 | 170 | 51/51 | 100.00% | 51/51 | 7/0/0 |  | quest-metadata-initialization |
| match | creature_spawn_slot_alloc | 0x00430ad0 | 30 | 10/10 | 100.00% | 10/10 | 2/0/0 |  | creature-spawn-slot-pool |
| wip | creature_spawn_template | 0x00430af0 | 14099 | 2950/3159 | 63.91% | 26/3159 | 315/0/1 |  | gameplay-spawn-switch |
| match | quest_spawn_table_empty | 0x00434220 | 39 | 16/16 | 100.00% | 16/16 | 2/0/0 |  | quest-spawn-table-exhaustion |
| wip | quest_spawn_timeline_update | 0x00434250 | 368 | 113/115 | 91.23% | 51/115 | 13/0/0 |  | quest-spawn-timeline-dispatch |
| match | quest_database_advance_slot | 0x004343c0 | 30 | 12/12 | 100.00% | 12/12 | 0/0/0 |  | quest-database-slot-advance |
| wip | quest_build_fallback | 0x004343e0 | 150 | 32/32 | 87.50% | 12/32 | 7/0/0 |  | quest-fallback-builder |
| wip | quest_build_nagolipoli | 0x00434480 | 983 | 247/258 | 55.05% | 7/258 | 10/0/0 |  | quest-nagolipoli-rings-waves-lines |
| wip | quest_build_monster_blues | 0x00434860 | 348 | 95/95 | 82.11% | 9/95 | 2/0/0 |  | quest-monster-blues-modulo-wave-selector |
| wip | quest_build_the_gathering | 0x004349c0 | 725 | 134/134 | 89.55% | 12/134 | 0/0/0 |  | quest-the-gathering-fixed-table |
| wip | quest_build_army_of_three | 0x00434ca0 | 608 | 116/116 | 86.21% | 10/116 | 0/0/0 |  | quest-army-of-three-fixed-formations |
| wip | quest_build_knee_deep_in_the_dead | 0x00434f00 | 541 | 141/141 | 95.74% | 3/141 | 17/0/0 |  | quest-knee-deep-escalating-zombies |
| wip | quest_build_the_gang_wars | 0x00435120 | 424 | 92/92 | 86.96% | 4/92 | 7/0/0 |  | quest-gang-wars-alternating-formations |
| wip | quest_build_the_fortress | 0x004352d0 | 429 | 102/102 | 96.08% | 21/102 | 8/0/0 |  | quest-fortress-overwritten-grid-seed |
| wip | quest_build_cross_fire | 0x00435480 | 390 | 76/76 | 81.58% | 10/76 | 2/0/0 |  | quest-cross-fire-fixed-table |
| wip | quest_build_the_beating | 0x00435610 | 649 | 166/166 | 53.61% | 22/166 | 7/0/0 |  | quest-the-beating-four-lines |
| wip | quest_build_the_spanking_of_the_dead | 0x004358a0 | 391 | 94/94 | 60.64% | 4/94 | 5/0/0 |  | quest-spanking-of-the-dead-spiral |
| wip | quest_build_hidden_evil | 0x00435a30 | 407 | 101/101 | 97.03% | 10/101 | 10/0/0 |  | quest-hidden-evil-fixed-waves |
| wip | quest_build_land_hostile | 0x00435bd0 | 239 | 53/53 | 92.45% | 19/53 | 2/0/0 |  | quest-land-hostile-builder |
| wip | quest_build_minor_alien_breach | 0x00435cc0 | 466 | 135/135 | 91.85% | 2/135 | 7/0/0 |  | quest-minor-alien-breach-escalating-edges |
| wip | quest_build_alien_squads | 0x00435ea0 | 507 | 108/108 | 89.81% | 10/108 | 0/0/0 |  | quest-alien-squads-fixed-corners |
| match | quest_build_zombie_masters | 0x004360a0 | 128 | 31/31 | 100.00% | 31/31 | 2/0/0 |  | quest-zombie-masters |
| wip | quest_build_8_legged_terror | 0x00436120 | 213 | 68/68 | 92.65% | 14/68 | 4/0/0 |  | quest-eight-legged-terror-builder |
| wip | quest_build_ghost_patrols | 0x00436200 | 334 | 90/90 | 81.11% | 14/90 | 5/0/0 |  | quest-ghost-patrols-cursor |
| wip | quest_build_the_random_factor | 0x00436350 | 237 | 74/74 | 90.54% | 16/74 | 7/0/0 |  | quest-random-factor-builder |
| wip | quest_build_spider_wave_syndrome | 0x00436440 | 95 | 31/31 | 83.87% | 12/31 | 2/0/0 |  | quest-spider-wave-syndrome |
| wip | quest_build_nesting_grounds | 0x004364a0 | 626 | 138/138 | 97.10% | 10/138 | 15/0/0 |  | quest-nesting-grounds-fixed-nests |
| wip | quest_build_alien_dens | 0x00436720 | 249 | 60/60 | 68.33% | 4/60 | 1/0/0 |  | quest-alien-dens-builder |
| wip | quest_build_arachnoid_farm | 0x00436820 | 382 | 112/112 | 93.75% | 12/112 | 10/0/0 |  | quest-arachnoid-farm-three-spawner-lines |
| wip | quest_build_gauntlet | 0x004369a0 | 614 | 182/182 | 80.22% | 31/182 | 25/0/0 |  | quest-gauntlet-rings-and-edges |
| wip | quest_build_syntax_terror | 0x00436c10 | 339 | 106/104 | 49.52% | 2/104 | 1/0/0 |  | quest-syntax-terror-polynomial-spawners |
| wip | quest_build_spider_spawns | 0x00436d70 | 365 | 73/73 | 87.67% | 2/73 | 0/0/0 |  | quest-spider-spawns-fixed-table |
| match | quest_build_two_fronts | 0x00436ee0 | 383 | 112/112 | 100.00% | 112/112 | 3/0/0 |  | quest-two-fronts-cardinal-waves |
| wip | quest_build_survival_of_the_fastest | 0x00437060 | 861 | 217/228 | 62.02% | 5/228 | 0/0/0 |  | quest-survival-fastest-shared-index-path |
| wip | quest_build_spideroids | 0x004373c0 | 224 | 62/62 | 98.39% | 5/62 | 3/0/0 |  | quest-spideroids-builder |
| match | quest_build_evil_zombies_at_large | 0x004374a0 | 244 | 81/81 | 100.00% | 81/81 | 6/0/0 |  | quest-evil-zombies-at-large-builder |
| wip | quest_build_everred_pastures | 0x004375a0 | 367 | 114/114 | 92.11% | 30/114 | 7/0/0 |  | quest-everred-pastures-cardinal-waves |
| wip | quest_build_lizard_kings | 0x00437710 | 254 | 67/66 | 78.20% | 7/66 | 6/0/0 |  | quest-lizard-kings-builder |
| wip | quest_build_sweep_stakes | 0x00437810 | 258 | 75/76 | 75.50% | 6/76 | 7/0/0 |  | quest-sweep-stakes-builder |
| wip | quest_build_deja_vu | 0x00437920 | 209 | 62/63 | 83.20% | 1/63 | 4/0/0 |  | quest-deja-vu-radial-waves |
| wip | quest_build_target_practice | 0x00437a00 | 240 | 69/69 | 89.86% | 23/69 | 8/0/0 |  | quest-target-practice-radial-builder |
| wip | quest_build_major_alien_breach | 0x00437af0 | 167 | 48/48 | 95.83% | 12/48 | 0/0/0 |  | quest-major-alien-breach-builder |
| wip | quest_build_land_of_lizards | 0x00437ba0 | 204 | 46/46 | 93.48% | 8/46 | 0/0/0 |  | quest-land-of-lizards |
| wip | quest_build_the_lizquidation | 0x00437c70 | 245 | 79/79 | 34.18% | 4/79 | 2/0/0 |  | quest-the-lizquidation-builder |
| wip | quest_build_zombie_time | 0x00437d70 | 152 | 50/50 | 82.00% | 16/50 | 3/0/0 |  | quest-zombie-time-builder |
| wip | quest_build_frontline_assault | 0x00437e10 | 285 | 81/84 | 75.15% | 10/84 | 1/0/0 |  | quest-frontline-assault-builder |
| wip | quest_build_the_collaboration | 0x00437f30 | 286 | 86/86 | 77.91% | 22/86 | 7/0/0 |  | quest-the-collaboration-builder |
| wip | quest_build_the_blighting | 0x00438050 | 624 | 190/190 | 94.74% | 17/190 | 11/0/0 |  | quest-the-blighting-fixed-spawners |
| wip | quest_build_the_annihilation | 0x004382c0 | 278 | 77/77 | 74.03% | 15/77 | 1/0/0 |  | quest-the-annihilation-builder |
| wip | quest_build_the_massacre | 0x004383e0 | 184 | 61/61 | 88.52% | 16/61 | 4/0/0 |  | quest-the-massacre-builder |
| match | quest_build_the_killing | 0x004384a0 | 602 | 173/173 | 100.00% | 173/173 | 14/0/0 |  | quest-the-killing-discarded-rng-cycle |
| wip | quest_build_lizard_zombie_pact | 0x00438700 | 311 | 95/95 | 56.84% | 2/95 | 3/0/0 |  | quest-lizard-zombie-pact-builder |
| wip | quest_build_lizard_raze | 0x00438840 | 254 | 77/77 | 79.22% | 16/77 | 3/0/0 |  | quest-lizard-raze-builder |
| match | quest_build_surrounded_by_reptiles | 0x00438940 | 242 | 68/68 | 100.00% | 68/68 | 4/0/0 |  | quest-surrounded-by-reptiles-builder |
| wip | quest_build_the_unblitzkrieg | 0x00438a40 | 975 | 291/291 | 70.10% | 12/291 | 0/0/0 |  | quest-unblitzkrieg-perimeter-sweeps |
| wip | quest_build_the_end_of_all | 0x00438e10 | 692 | 173/174 | 66.28% | 4/174 | 18/0/0 |  | quest-the-end-of-all-fixed-rings |
| wip | quest_build_spiders_inc | 0x004390d0 | 346 | 106/105 | 69.19% | 9/105 | 8/0/0 |  | quest-spiders-inc-staged-spider-waves |
| match | quest_database_init | 0x00439230 | 5466 | 1384/1384 | 100.00% | 1384/1384 | 503/0/0 |  | quest-content-database-initialization |
| wip | quest_start_selected | 0x0043a790 | 434 | 116/116 | 91.38% | 80/116 | 47/0/0 |  | quest-start-state-and-spawn-table |
| match | highscore_date_checksum | 0x0043a950 | 262 | 97/97 | 100.00% | 97/97 | 0/0/0 |  | highscore-iso-week-checksum |
| match | highscore_submit_full_version_guard | 0x0043aa60 | 38 | 12/12 | 100.00% | 12/12 | 4/0/0 |  | highscore-submit-validation |
| match | highscore_record_pack_for_submit | 0x0043aa90 | 113 | 44/44 | 100.00% | 44/44 | 0/0/0 |  | highscore-submit-packing |
| match | highscore_read_record | 0x0043ab10 | 179 | 80/80 | 100.00% | 80/80 | 5/0/0 |  | highscore-record-read-validation |
| match | highscore_record_equals | 0x0043abd0 | 151 | 74/74 | 100.00% | 74/74 | 0/0/0 |  | highscore-record-equality |
| match | highscore_update_record | 0x0043ac70 | 255 | 95/95 | 100.00% | 95/95 | 13/0/0 |  | highscore-record-in-place-update |
| match | highscore_write_record | 0x0043ad70 | 318 | 103/103 | 100.00% | 103/103 | 13/0/0 |  | highscore-record-write-encoding |
| match | highscore_compare_survival_score_desc | 0x0043aeb0 | 32 | 13/13 | 100.00% | 13/13 | 0/0/0 |  | highscore-survival-score-order |
| match | highscore_compare_rush_field32_desc | 0x0043aed0 | 32 | 13/13 | 100.00% | 13/13 | 0/0/0 |  | highscore-rush-time-order |
| match | highscore_compare_quest_field32_asc_nonzero_first | 0x0043aef0 | 53 | 22/22 | 100.00% | 22/22 | 0/0/0 |  | highscore-quest-time-order |
| match | highscore_find_name_entry | 0x0043af30 | 101 | 48/48 | 100.00% | 48/48 | 2/0/0 |  | highscore-name-lookup |
| wip | highscore_load_table | 0x0043afa0 | 1198 | 339/354 | 67.53% | 0/354 | 51/0/0 |  | highscore-table-load-filter-sort |
| match | highscore_save_record | 0x0043b450 | 182 | 70/70 | 100.00% | 70/70 | 16/0/0 |  | highscore-record-save-coordinator |
| match | highscore_save_active | 0x0043b510 | 12 | 4/4 | 100.00% | 4/4 | 2/0/0 |  | highscore-active-record-save |
| wip | highscore_rank_index | 0x0043b520 | 133 | 51/51 | 58.82% | 4/51 | 4/0/0 |  | highscore-rank-lookup |
| match | highscore_build_path | 0x0043b5b0 | 402 | 104/104 | 100.00% | 104/104 | 54/0/0 | msvc6.5 /O2 /GB /W3 /GR- /TP | highscore-mode-path-builder |
| match | highscore_record_init | 0x0043b750 | 165 | 46/46 | 100.00% | 46/46 | 17/0/0 |  | highscore-record-finalization |
| match | j_highscore_load_table | 0x0043b800 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | tail-thunk-to-highscore-loader |
| match | sfx_entry_reset_runtime_state | 0x0043b810 | 54 | 19/19 | 100.00% | 19/19 | 0/0/0 |  | audio-entry-initialization |
| match | buffer_reader_init | 0x0043b850 | 30 | 6/6 | 100.00% | 6/6 | 3/0/0 |  | resource-buffer-reader |
| match | buffer_reader_seek | 0x0043b870 | 10 | 3/3 | 100.00% | 3/3 | 1/0/0 |  | resource-buffer-reader |
| match | buffer_reader_read_u16 | 0x0043b880 | 25 | 6/6 | 100.00% | 6/6 | 3/0/0 |  | resource-buffer-reader |
| match | buffer_reader_read_u32 | 0x0043b8a0 | 24 | 6/6 | 100.00% | 6/6 | 3/0/0 |  | resource-buffer-reader |
| match | buffer_reader_skip | 0x0043b8c0 | 19 | 5/5 | 100.00% | 5/5 | 2/0/0 |  | resource-buffer-reader |
| match | buffer_reader_find_tag | 0x0043b8e0 | 87 | 41/41 | 100.00% | 41/41 | 4/0/0 |  | resource-buffer-reader |
| match | resource_pack_read_cstring | 0x0043b940 | 62 | 24/24 | 100.00% | 24/24 | 3/0/0 |  | resource-pack-cstring |
| match | resource_pack_set | 0x0043b980 | 95 | 37/37 | 100.00% | 37/37 | 7/0/0 |  | resource-pack-selection |
| match | resource_open_read | 0x0043b9e0 | 233 | 88/88 | 100.00% | 88/88 | 21/0/0 |  | resource-pack-lookup |
| match | resource_close | 0x0043bad0 | 17 | 7/7 | 100.00% | 7/7 | 2/0/0 |  | resource-file-lifecycle |
| match | dsound_init | 0x0043baf0 | 289 | 102/102 | 100.00% | 102/102 | 6/0/0 |  | audio-directsound-initialization |
| match | dsound_shutdown | 0x0043bc20 | 26 | 8/8 | 100.00% | 8/8 | 2/0/0 |  | audio-directsound-lifecycle |
| match | dsound_restore_buffer | 0x0043bc40 | 81 | 34/34 | 100.00% | 34/34 | 3/0/0 |  | audio-directsound-buffer-restore |
| match | resource_read_alloc | 0x0043bca0 | 75 | 33/33 | 100.00% | 33/33 | 5/0/0 |  | resource-owned-read |
| wip | sfx_entry_load_ogg | 0x0043bcf0 | 304 | 99/99 | 97.98% | 78/99 | 10/0/0 |  | audio-ogg-resident-load |
| match | sfx_entry_seek | 0x0043be20 | 56 | 24/24 | 100.00% | 24/24 | 1/0/0 |  | audio-entry-playback |
| wip | sfx_entry_start_playback | 0x0043be60 | 215 | 93/93 | 77.42% | 20/93 | 7/0/0 |  | audio-entry-voice-start |
| match | sfx_entry_resume | 0x0043bf40 | 27 | 12/12 | 100.00% | 12/12 | 0/0/0 |  | audio-entry-playback |
| match | sfx_entry_stop | 0x0043bf60 | 60 | 29/29 | 100.00% | 29/29 | 0/0/0 |  | audio-entry-playback |
| wip | sfx_entry_set_volume | 0x0043bfa0 | 120 | 45/45 | 86.67% | 2/45 | 5/0/0 |  | audio-entry-volume |
| match | sfx_entry_load_wav | 0x0043c020 | 104 | 44/44 | 100.00% | 44/44 | 5/0/0 |  | audio-wav-load |
| match | sfx_release_entry | 0x0043c090 | 119 | 52/52 | 100.00% | 52/52 | 4/0/0 |  | audio-entry-lifecycle |
| match | wav_parse_into_entry | 0x0043c110 | 274 | 87/87 | 100.00% | 87/87 | 15/0/0 |  | audio-wav-parser |
| match | sfx_entry_upload_buffer | 0x0043c230 | 123 | 57/57 | 100.00% | 57/57 | 1/0/0 |  | audio-directsound-buffer-upload |
| match | sfx_entry_create_buffers | 0x0043c2b0 | 238 | 91/91 | 100.00% | 91/91 | 9/0/0 |  | audio-directsound-buffer-create |
| match | music_entry_load_ogg | 0x0043c3a0 | 380 | 125/125 | 100.00% | 125/125 | 13/0/0 |  | audio-ogg-stream-load |
| match | music_stream_update | 0x0043c520 | 109 | 42/42 | 100.00% | 42/42 | 1/0/0 |  | audio-music-stream-update |
| match | music_stream_fill | 0x0043c590 | 221 | 86/86 | 100.00% | 86/86 | 4/0/0 |  | audio-music-stream-fill |
| match | sfx_entry_table_init_thunk | 0x0043c670 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | audio-sfx-entry-table-init-thunk |
| match | sfx_entry_table_init | 0x0043c680 | 31 | 12/12 | 100.00% | 12/12 | 2/0/0 |  | audio-sfx-entry-table-init |
| match | audio_asset_id_table_init_thunk | 0x0043c6a0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | audio-asset-id-table-init-thunk |
| match | audio_asset_id_table_init | 0x0043c6b0 | 17 | 7/7 | 100.00% | 7/7 | 1/0/0 |  | audio-asset-id-table-init |
| match | music_entry_table_init_thunk | 0x0043c6d0 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | audio-music-entry-table-init-thunk |
| match | music_entry_table_init | 0x0043c6e0 | 31 | 12/12 | 100.00% | 12/12 | 2/0/0 |  | audio-music-entry-table-init |
| match | sfx_release_sample | 0x0043c700 | 57 | 20/20 | 100.00% | 20/20 | 3/0/0 |  | audio-slot-lifecycle |
| match | sfx_load_sample | 0x0043c740 | 389 | 134/134 | 100.00% | 134/134 | 29/0/0 |  | audio-sample-slot-loader |
| match | music_load_track | 0x0043c8d0 | 139 | 53/53 | 100.00% | 53/53 | 12/0/0 |  | music-track-slot-loader |
| match | music_queue_track | 0x0043c960 | 27 | 8/8 | 100.00% | 8/8 | 3/0/0 |  | audio-music-playlist |
| match | music_release_track | 0x0043c980 | 57 | 20/20 | 100.00% | 20/20 | 3/0/0 |  | audio-slot-lifecycle |
| match | audio_init_music | 0x0043c9c0 | 212 | 51/51 | 100.00% | 51/51 | 29/0/0 |  | audio-music-initialization |
| match | audio_init_sfx | 0x0043caa0 | 1262 | 270/270 | 100.00% | 270/270 | 235/0/0 |  | audio-sfx-registry-initialization |
| match | sfx_system_init | 0x0043cf90 | 214 | 59/59 | 100.00% | 59/59 | 28/0/0 |  | audio-system-initialization |
| match | sfx_release_all | 0x0043d070 | 91 | 24/24 | 100.00% | 24/24 | 13/0/0 |  | audio-system-lifecycle |
| match | music_release_all | 0x0043d0d0 | 55 | 16/16 | 100.00% | 16/16 | 7/0/0 |  | audio-system-lifecycle |
| match | audio_shutdown_all | 0x0043d110 | 15 | 3/3 | 100.00% | 3/3 | 3/0/0 |  | audio-subsystem-teardown |
| match | sfx_play | 0x0043d120 | 320 | 93/93 | 100.00% | 93/93 | 29/0/0 |  | audio-centered-sfx-playback |
| match | sfx_play_panned | 0x0043d260 | 386 | 110/110 | 100.00% | 110/110 | 34/0/0 |  | position-panned-sfx-playback |
| match | audio_update | 0x0043d3f0 | 102 | 32/32 | 100.00% | 32/32 | 10/0/0 |  | audio-frame-update |
| match | sfx_play_exclusive | 0x0043d460 | 239 | 66/66 | 100.00% | 66/66 | 23/0/0 |  | audio-exclusive-music-playback |
| match | sfx_mute_all | 0x0043d550 | 87 | 31/31 | 100.00% | 31/31 | 6/0/0 |  | audio-mute-recursion |
| wip | sfx_update_mute_fades | 0x0043d5b0 | 374 | 116/118 | 83.76% | 3/118 | 26/0/0 |  | audio-mute-fade-state-machine |
| match | audio_suspend_channels | 0x0043d730 | 58 | 19/19 | 100.00% | 19/19 | 6/0/0 |  | audio-suspend-resume |
| match | audio_resume_channels | 0x0043d770 | 73 | 26/26 | 100.00% | 26/26 | 7/0/0 |  | audio-suspend-resume |
| match | sfx_is_unmuted | 0x0043d7c0 | 30 | 11/11 | 100.00% | 11/11 | 2/0/0 |  | audio-mute-state |
| match | ui_focus_set | 0x0043d7e0 | 75 | 25/25 | 100.00% | 25/25 | 6/0/0 |  | ui-focus-selection |
| match | ui_focus_update | 0x0043d830 | 268 | 78/78 | 100.00% | 78/78 | 27/0/0 |  | ui-focus-navigation |
| match | ui_focus_draw | 0x0043d940 | 104 | 24/24 | 100.00% | 24/24 | 4/0/0 |  | ui-focus-highlight |
| match | ui_segmented_slider_update | 0x0043d9b0 | 714 | 213/213 | 100.00% | 213/213 | 35/0/0 |  | ui-segmented-slider-widget |
| match | ui_checkbox_update | 0x0043dc80 | 622 | 188/188 | 100.00% | 188/188 | 27/0/0 |  | ui-checkbox-widget |
| wip | ui_scrollbar_update | 0x0043def0 | 1767 | 472/479 | 54.05% | 0/479 | 59/0/0 |  | ui-scrollbar-wheel-drag-navigation-and-column-rendering |
| match | ui_menu_item_update | 0x0043e5e0 | 548 | 153/153 | 100.00% | 153/153 | 38/0/0 |  | ui-menu-item-widget |
| match | ui_menu_hover_color_destroy | 0x0043e810 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | ui-menu-hover-color-empty-destructor |
| match | ui_menu_idle_color_destroy | 0x0043e820 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | ui-menu-idle-color-empty-destructor |
| match | ui_button_update | 0x0043e830 | 1215 | 347/347 | 100.00% | 347/347 | 61/0/0 |  | ui-button-focus-animation-render-and-activation |
| match | ui_text_input_update | 0x0043ecf0 | 716 | 203/203 | 100.00% | 203/203 | 36/0/0 |  | ui-text-input-widget |
| wip | ui_list_widget_update | 0x0043efc0 | 1420 | 402/403 | 90.93% | 32/403 | 50/0/0 |  | ui-dropdown-focus-navigation-hover-and-row-selection |
| wip | statistics_menu_update | 0x0043f550 | 2877 | 675/676 | 88.82% | 280/676 | 264/0/5 |  | statistics-playtime-network-status-and-navigation |
| wip | unlocked_weapons_database_update | 0x00440110 | 2086 | 522/523 | 82.87% | 9/523 | 140/0/2 |  | unlocked-weapon-list-and-detail-panel |
| match | unlocked_weapons_back_button_destroy | 0x00440940 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | unlocked-weapons-back-button-empty-destructor |
| match | unlocked_weapons_scrollbar_destroy | 0x00440950 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | unlocked-weapons-scrollbar-empty-destructor |
| wip | unlocked_perks_database_update | 0x00440960 | 2065 | 508/511 | 85.38% | 0/511 | 135/0/2 |  | unlocked-perk-list-prerequisite-and-description-panel |
| match | unlocked_perks_back_button_destroy | 0x00441180 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | unlocked-perks-back-button-empty-destructor |
| match | unlocked_perks_scrollbar_destroy | 0x00441190 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | unlocked-perks-scrollbar-empty-destructor |
| match | highscore_card_draw_horizontal_divider | 0x004411c0 | 83 | 23/23 | 100.00% | 23/23 | 6/0/0 |  | highscore-card-divider |
| match | highscore_card_draw_vertical_divider | 0x00441220 | 71 | 20/20 | 100.00% | 20/20 | 5/0/0 |  | highscore-card-divider |
| match | highscore_format_date_label | 0x00441270 | 256 | 80/80 | 100.00% | 80/80 | 18/0/0 |  | highscore-date-label |
| match | ui_text_input_render | 0x004413a0 | 3504 | 924/924 | 100.00% | 924/924 | 243/0/0 |  | highscore-result-card-renderer |
| match | ui_update_notice_update | 0x00442150 | 614 | 156/156 | 100.00% | 156/156 | 47/0/0 |  | update-available-notice |
| wip | highscore_screen_update | 0x004423d0 | 8026 | 1954/2004 | 75.85% | 41/2004 | 567/0/8 |  | highscore-list-filters-online-sync-and-state-routing |
| match | highscore_game_mode_list_destroy | 0x00444330 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-game-mode-list-empty-destructor |
| match | highscore_player_count_list_destroy | 0x00444340 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-player-count-list-empty-destructor |
| match | highscore_date_filter_list_destroy | 0x00444350 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-date-filter-list-empty-destructor |
| match | highscore_online_scores_checkbox_destroy | 0x00444360 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-online-scores-checkbox-empty-destructor |
| match | highscore_back_button_destroy | 0x00444370 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-back-button-empty-destructor |
| match | highscore_play_button_destroy | 0x00444380 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-play-button-empty-destructor |
| match | highscore_update_button_destroy | 0x00444390 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-update-button-empty-destructor |
| match | highscore_score_scrollbar_destroy | 0x004443a0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-score-scrollbar-empty-destructor |
| match | highscore_hardcore_checkbox_destroy | 0x004443b0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | highscore-hardcore-checkbox-empty-destructor |
| match | ui_profile_menu_update | 0x004443c0 | 1033 | 261/261 | 100.00% | 261/261 | 109/0/0 |  | profile-saved-name-list-editing |
| match | creature_spawn_tinted | 0x00444810 | 364 | 92/92 | 100.00% | 92/92 | 34/0/0 |  | gameplay-typo-creature-spawn |
| wip | player_fire_weapon | 0x00444980 | 1518 | 378/378 | 86.77% | 8/378 | 141/0/0 |  | typo-player-frame-and-shotgun-fire |
| match | typo_word_pick_fragment | 0x00444f70 | 356 | 117/117 | 100.00% | 117/117 | 54/0/0 |  | typo-random-name-fragment-table |
| match | typo_word_pick_highscore_name | 0x004451b0 | 345 | 123/123 | 100.00% | 123/123 | 20/0/0 |  | typo-highscore-name-cache |
| match | typo_target_name_is_unique | 0x00445310 | 110 | 50/50 | 100.00% | 50/50 | 3/0/0 |  | typo-target-uniqueness |
| wip | typo_target_name_assign_random | 0x00445380 | 522 | 173/173 | 76.88% | 17/173 | 27/0/0 |  | typo-random-target-name-policy |
| match | typo_target_find_by_name | 0x00445590 | 98 | 42/42 | 100.00% | 42/42 | 3/0/0 |  | typo-target-lookup |
| match | typo_target_name_draw_labels | 0x00445600 | 434 | 111/111 | 100.00% | 111/111 | 20/0/0 |  | typo-active-creature-name-labels |
| wip | typo_gameplay_update_and_render | 0x004457c0 | 2082 | 508/508 | 98.43% | 33/508 | 194/0/0 |  | typo-shooter-gameplay-loop |
| match | input_any_key_pressed | 0x00446000 | 40 | 16/16 | 100.00% | 16/16 | 1/0/0 |  | input-any-key |
| match | input_primary_just_pressed | 0x00446030 | 188 | 62/62 | 100.00% | 62/62 | 14/0/0 |  | input-primary-edge |
| match | input_primary_is_down | 0x004460f0 | 74 | 24/24 | 100.00% | 24/24 | 5/0/0 |  | input-primary-held |
| match | ui_callback_noop | 0x00446140 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | ui-placeholder-callback |
| match | ui_get_element_index | 0x00446150 | 31 | 11/11 | 100.00% | 11/11 | 2/0/0 |  | ui-element-index |
| match | ui_elements_reset_state | 0x00446170 | 31 | 10/10 | 100.00% | 10/10 | 2/0/0 |  | ui-element-state-reset |
| match | ui_elements_max_timeline | 0x00446190 | 35 | 13/13 | 100.00% | 13/13 | 2/0/0 |  | ui-element-timeline-extent |
| wip | game_state_set | 0x004461c0 | 1854 | 393/399 | 85.35% | 166/399 | 161/1/0 |  | game-state-ui-transition-dispatch |
| match | ui_element_update | 0x00446900 | 831 | 226/226 | 100.00% | 226/226 | 29/0/0 |  | ui-element-interaction-and-transition |
| wip | ui_element_render | 0x00446c40 | 1801 | 515/521 | 83.40% | 7/521 | 59/0/0 |  | ui-focus-panel-offset-and-counter-overlay-rendering |
| match | ui_menu_main_click_mods | 0x00447350 | 18 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | ui-menu-state-callback |
| match | ui_menu_main_click_options | 0x00447370 | 18 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | ui-menu-state-callback |
| match | ui_menu_main_click_statistics | 0x00447390 | 67 | 16/16 | 100.00% | 16/16 | 10/0/0 |  | ui-menu-statistics-audio |
| match | ui_menu_main_click_controls | 0x004473e0 | 18 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | ui-menu-state-callback |
| match | ui_menu_main_click_play_game | 0x00447400 | 18 | 3/3 | 100.00% | 3/3 | 2/0/0 |  | ui-menu-state-callback |
| match | ui_menu_click_back_contextual | 0x00447420 | 45 | 12/12 | 100.00% | 12/12 | 5/0/0 |  | ui-menu-contextual-back |
| match | ui_menu_main_click_quit | 0x00447450 | 61 | 15/15 | 100.00% | 15/15 | 9/0/0 |  | ui-menu-quit |
| match | ui_menu_pause_click_resume | 0x00447490 | 67 | 18/18 | 100.00% | 18/18 | 7/0/0 |  | ui-menu-resume |
| match | ui_menu_pause_click_main_menu | 0x004474e0 | 160 | 40/40 | 100.00% | 40/40 | 22/0/0 |  | pause-menu-plugin-exit |
| match | config_apply_detail_preset | 0x00447580 | 57 | 15/15 | 100.00% | 15/15 | 8/0/0 |  | graphics-detail-preset-flags |
| wip | options_menu_update | 0x004475d0 | 1621 | 372/377 | 69.96% | 8/377 | 138/0/8 |  | options-audio-detail-input-and-controls-navigation |
| match | input_configure_for_label | 0x00447c90 | 58 | 18/18 | 100.00% | 18/18 | 8/0/0 |  | input-configuration-label |
| match | input_scheme_label | 0x00447cf0 | 53 | 17/17 | 100.00% | 17/17 | 7/0/0 |  | input-scheme-label |
| wip | quest_select_menu_update | 0x00447d40 | 3436 | 782/803 | 71.17% | 0/803 | 222/0/14 |  | quest-stage-picker-hardcore-gating-and-start-routing |
| match | quest_select_back_button_destroy | 0x00448ab0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-back-button-empty-destructor |
| match | quest_select_hardcore_checkbox_destroy | 0x00448ac0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-hardcore-checkbox-empty-destructor |
| match | quest_select_unused_orange_color_destroy | 0x00448ad0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-unused-orange-color-empty-destructor |
| match | quest_select_hovered_stage_color_destroy | 0x00448ae0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-hovered-stage-color-empty-destructor |
| match | quest_select_selected_stage_color_destroy | 0x00448af0 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-selected-stage-color-empty-destructor |
| match | quest_select_title_color_destroy | 0x00448b00 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-title-color-empty-destructor |
| match | quest_select_unused_blue_dim_color_destroy | 0x00448b10 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-unused-blue-dim-color-empty-destructor |
| match | quest_select_unused_blue_color_destroy | 0x00448b20 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-unused-blue-color-empty-destructor |
| match | quest_select_row_hover_color_destroy | 0x00448b30 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-row-hover-color-empty-destructor |
| match | quest_select_row_idle_color_destroy | 0x00448b40 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | quest-select-row-idle-color-empty-destructor |
| wip | input_detect_active_analog_axis | 0x00448b50 | 377 | 102/103 | 59.51% | 2/103 | 13/0/0 |  | input-analog-axis-detection |
| wip | controls_menu_update | 0x00448cd0 | 21289 | 4488/5421 | 50.80% | 4/5421 | 863/2/34 |  | controls-device-schemes-key-axis-rebinding-and-render-flow |
| match | vec2_add_out | 0x0044ecf0 | 26 | 9/9 | 100.00% | 9/9 | 0/0/0 |  | x87-vector-add |
| wip | play_game_menu_update | 0x0044ed80 | 3238 | 776/777 | 87.44% | 120/777 | 275/0/28 |  | play-game-mode-buttons-player-count-and-routing |
| match | play_game_player_count_list_destroy | 0x0044fa30 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | play-game-player-count-list-empty-destructor |
| match | play_game_tutorial_button_destroy | 0x0044fa40 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | play-game-tutorial-button-empty-destructor |
| match | play_game_hardcore_checkbox_destroy | 0x0044fa50 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | play-game-hardcore-checkbox-empty-destructor |
| match | play_game_typo_button_destroy | 0x0044fa60 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | play-game-typo-button-empty-destructor |
| match | play_game_survival_button_destroy | 0x0044fa70 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | play-game-survival-button-empty-destructor |
| match | play_game_rush_button_destroy | 0x0044fa80 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | play-game-rush-button-empty-destructor |
| match | play_game_quests_button_destroy | 0x0044fa90 | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 |  | play-game-quests-button-empty-destructor |
| match | ui_element_init_defaults | 0x0044faa0 | 173 | 40/40 | 100.00% | 40/40 | 3/0/0 |  | ui-element-default-state |
| wip | ui_element_layout_calc | 0x0044fb50 | 288 | 86/86 | 95.35% | 16/86 | 6/0/0 |  | ui-element-layout-and-hover-uvs |
| match | ui_menu_main_click_buy_full_version | 0x0044fc70 | 39 | 11/11 | 100.00% | 11/11 | 5/0/0 |  | shareware-purchase-link |
| match | ui_menu_main_click_recheck_full_version | 0x0044fca0 | 8 | 2/2 | 100.00% | 2/2 | 1/0/0 |  | full-version-recheck |
| wip | ui_menu_layout_init | 0x0044fcb0 | 7237 | 1302/1422 | 55.43% | 1/1422 | 305/0/48 |  | menu-element-graph-layout-and-responsive-transforms |
| match | weapon_table_defaults_global_init_thunk | 0x00451900 | 5 | 1/1 | 100.00% | 1/1 | 1/0/0 |  | weapon-table-default-global-initialization-thunk |
| match | weapon_table_defaults_global_init | 0x00451910 | 150 | 47/47 | 100.00% | 47/47 | 2/0/0 |  | weapon-table-default-global-initialization |
| match | weapon_table_init | 0x004519b0 | 4885 | 1000/1000 | 100.00% | 1000/1000 | 477/0/0 |  | weapon-metadata-database |
| match | weapon_pick_random_available | 0x00452cd0 | 107 | 36/36 | 100.00% | 36/36 | 8/0/0 |  | gameplay-weapon-rng |
| match | weapon_assign_player | 0x00452d40 | 254 | 61/61 | 100.00% | 61/61 | 26/0/0 |  | gameplay-weapon-assignment |
| match | weapon_refresh_available | 0x00452e40 | 161 | 48/48 | 100.00% | 48/48 | 17/0/0 |  | gameplay-weapon-unlocks |
| match | float_near_equal | 0x00452ef0 | 45 | 17/17 | 100.00% | 17/17 | 2/0/0 | msvc6.5pp /O1 /GB /W3 /GR- | math-float-epsilon |
| match | vec2_normalize_dispatch_init | 0x00452f1d | 13 | 3/3 | 100.00% | 3/3 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | lazy-vector-normalize-dispatch |
| match | vec2_normalize_dispatch | 0x00452f2a | 6 | 1/1 | 100.00% | 1/1 | 1/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | vector-normalize-dispatch-thunk |
| match | vec2_normalize_safe | 0x00455587 | 141 | 57/57 | 100.00% | 57/57 | 3/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | vector-safe-normalize |
| match | renderer_select_backend | 0x004566d3 | 221 | 72/72 | 100.00% | 72/72 | 20/0/0 | msvc7.0 /O1 /Oi /G6 /Oy- /W3 /GR- | renderer-vector-backend-selection |
| wip | vec3_transform_coord | 0x0045eac0 | 139 | 54/37 | 17.58% | 0/37 | 0/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | 3dnow-vector-coordinate-transform |

## grim.dll

**217/1176** functions, **26687/289925** bytes (**9.2%**), **217/225** scratches verified.

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
| match | grim_format_info_lookup | 0x1000aaa6 | 36 | 12/12 | 100.00% | 12/12 | 3/0/0 | msvc6.5pp /O1 /GB /W3 /GR- | grim-d3d-format-descriptor-lookup |
| match | float_near_equal | 0x1000cbff | 45 | 17/17 | 100.00% | 17/17 | 2/0/0 | msvc6.5pp /O1 /GB /W3 /GR- | grim-math-float-epsilon |
| match | grim_vertex_space_converter_destroy | 0x1001692e | 19 | 5/5 | 100.00% | 5/5 | 2/0/0 | msvc6.5pp /O1 /GB /W3 /GR- | grim-converted-vertex-buffer-destruction |
| match | grim_pixel_format_quantize_color_key_yuv | 0x10016c3b | 1 | 1/1 | 100.00% | 1/1 | 0/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-yuv-color-key-noop |
| wip | grim_pixel_format_destroy_dxt | 0x10016c3c | 160 | 51/49 | 66.00% | 6/49 | 7/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- /GX | grim-dxt-cache-destruction |
| wip | grim_pixel_format_quantize_color_key | 0x100173dc | 204 | 74/74 | 95.95% | 7/74 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-color-key-roundtrip |
| match | grim_apply_color_key | 0x100174a8 | 112 | 46/46 | 100.00% | 46/46 | 0/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-color-key-mask |
| match | grim_pixel_format_read_r8g8b8 | 0x100192a7 | 140 | 49/49 | 100.00% | 49/49 | 2/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-r8g8b8-row-reader |
| match | grim_pixel_format_read_a8r8g8b8 | 0x10019333 | 166 | 56/56 | 100.00% | 56/56 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-a8r8g8b8-row-reader |
| match | grim_pixel_format_read_x8r8g8b8 | 0x100193d9 | 156 | 53/53 | 100.00% | 53/53 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-x8r8g8b8-row-reader |
| match | grim_pixel_format_read_r5g6b5 | 0x10019475 | 165 | 59/59 | 100.00% | 59/59 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-r5g6b5-row-reader |
| match | grim_pixel_format_read_x1r5g5b5 | 0x1001951a | 162 | 60/60 | 100.00% | 60/60 | 2/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-x1r5g5b5-row-reader |
| match | grim_pixel_format_read_a1r5g5b5 | 0x100195bc | 176 | 64/64 | 100.00% | 64/64 | 2/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-a1r5g5b5-row-reader |
| match | grim_pixel_format_read_a4r4g4b4 | 0x1001966c | 175 | 64/64 | 100.00% | 64/64 | 2/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-a4r4g4b4-row-reader |
| match | grim_pixel_format_read_a2b10g10r10 | 0x1001971b | 214 | 73/73 | 100.00% | 73/73 | 7/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-a2b10g10r10-row-reader |
| match | grim_pixel_format_read_g16r16 | 0x100197f1 | 146 | 50/50 | 100.00% | 50/50 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-g16r16-row-reader |
| match | grim_pixel_format_read_r3g3b2 | 0x10019883 | 162 | 58/58 | 100.00% | 58/58 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-r3g3b2-row-reader |
| match | grim_pixel_format_read_a8 | 0x10019925 | 114 | 41/41 | 100.00% | 41/41 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-a8-row-reader |
| match | grim_pixel_format_read_a8r3g3b2 | 0x10019997 | 178 | 63/63 | 100.00% | 63/63 | 4/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-a8r3g3b2-row-reader |
| match | grim_pixel_format_read_x4r4g4b4 | 0x10019a49 | 159 | 59/59 | 100.00% | 59/59 | 2/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-x4r4g4b4-row-reader |
| match | grim_pixel_format_read_a8p8 | 0x10019ae8 | 135 | 51/51 | 100.00% | 51/51 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-a8p8-palette-row-reader |
| match | grim_pixel_format_read_p8 | 0x10019b6f | 100 | 38/38 | 100.00% | 38/38 | 1/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-p8-palette-row-reader |
| match | grim_pixel_format_read_l8 | 0x10019bd3 | 110 | 39/39 | 100.00% | 39/39 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-l8-row-reader |
| match | grim_pixel_format_read_a8l8 | 0x10019c41 | 137 | 49/49 | 100.00% | 49/49 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-a8l8-row-reader |
| match | grim_pixel_format_read_a4l4 | 0x10019cca | 137 | 50/50 | 100.00% | 50/50 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-a4l4-row-reader |
| match | grim_pixel_format_read_v8u8 | 0x10019d53 | 130 | 47/47 | 100.00% | 47/47 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-v8u8-vector-row-reader |
| match | grim_pixel_format_read_l6v5u5 | 0x10019dd5 | 177 | 64/64 | 100.00% | 64/64 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-l6v5u5-vector-luminance-row-reader |
| match | grim_pixel_format_read_x8l8v8u8 | 0x10019e86 | 145 | 49/49 | 100.00% | 49/49 | 3/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-x8l8v8u8-vector-row-reader |
| match | grim_pixel_format_read_q8w8v8u8 | 0x10019f17 | 151 | 52/52 | 100.00% | 52/52 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-q8w8v8u8-vector-row-reader |
| match | grim_pixel_format_read_v16u16 | 0x10019fae | 131 | 46/46 | 100.00% | 46/46 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-v16u16-vector-row-reader |
| match | grim_pixel_format_read_w11v11u10 | 0x1001a031 | 186 | 63/63 | 100.00% | 63/63 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-w11v11u10-vector-row-reader |
| match | grim_pixel_format_read_a2w10v10u10 | 0x1001a0eb | 211 | 70/70 | 100.00% | 70/70 | 4/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-a2w10v10u10-vector-row-reader |
| match | grim_pixel_format_read_unorm16 | 0x1001a1be | 112 | 40/40 | 100.00% | 40/40 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-unorm16-row-reader |
| match | grim_pixel_format_read_al16 | 0x1001a22e | 142 | 48/48 | 100.00% | 48/48 | 3/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-al16-row-reader |
| match | grim_pixel_format_read_r16 | 0x1001a2bc | 140 | 49/49 | 100.00% | 49/49 | 2/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-r16-row-reader |
| match | grim_pixel_format_read_ar16 | 0x1001a348 | 224 | 77/77 | 100.00% | 77/77 | 6/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-ar16-row-reader |
| match | grim_pixel_format_ctor_r8g8b8 | 0x1001a428 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-r8g8b8-constructor |
| match | grim_pixel_format_init_yuv | 0x1001a444 | 248 | 69/69 | 100.00% | 69/69 | 7/0/0 | msvc6.5pp /O1 /Oi /G6 /Ob0 /W3 /GR- /GX | grim-yuv-format-base-constructor |
| match | grim_pixel_format_ctor_a8r8g8b8 | 0x1001a53c | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a8r8g8b8-constructor |
| match | grim_pixel_format_ctor_x8r8g8b8 | 0x1001a558 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-x8r8g8b8-constructor |
| match | grim_pixel_format_ctor_r5g6b5 | 0x1001a579 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-r5g6b5-constructor |
| match | grim_pixel_format_ctor_x1r5g5b5 | 0x1001a781 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-x1r5g5b5-constructor |
| match | grim_pixel_format_ctor_a1r5g5b5 | 0x1001a79d | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a1r5g5b5-constructor |
| match | grim_pixel_format_ctor_a4r4g4b4 | 0x1001aa8a | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a4r4g4b4-constructor |
| match | grim_pixel_format_ctor_r3g3b2 | 0x1001aaa6 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-r3g3b2-constructor |
| match | grim_pixel_format_ctor_a8 | 0x1001aac2 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a8-constructor |
| match | grim_pixel_format_ctor_a8r3g3b2 | 0x1001aade | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a8r3g3b2-constructor |
| match | grim_pixel_format_ctor_x4r4g4b4 | 0x1001aafa | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-x4r4g4b4-constructor |
| match | grim_pixel_format_write_yuv_cache | 0x1001ab16 | 141 | 45/45 | 100.00% | 45/45 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-yuv-cache-write |
| match | grim_pixel_format_ctor_a2b10g10r10 | 0x1001aba3 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a2b10g10r10-constructor |
| match | grim_pixel_format_read_yuv_cache | 0x1001abbf | 111 | 37/37 | 100.00% | 37/37 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-yuv-cache-read |
| match | grim_pixel_format_ctor_g16r16 | 0x1001ac2e | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-g16r16-constructor |
| match | grim_pixel_format_init_dxt | 0x1001ac4a | 498 | 109/109 | 100.00% | 109/109 | 12/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-dxt-format-base-constructor |
| match | grim_pixel_format_ctor_a8p8 | 0x1001ae3c | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a8p8-constructor |
| match | grim_pixel_format_scalar_deleting_destroy | 0x1001ae58 | 28 | 11/11 | 100.00% | 11/11 | 2/0/0 | msvc6.5pp /O1 /GB /W3 /GR- | grim-pixel-format-scalar-deleting-destructor |
| match | grim_pixel_format_ctor_p8 | 0x1001ae74 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-p8-constructor |
| match | grim_pixel_format_ctor_l8 | 0x1001ae90 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-l8-constructor |
| match | grim_pixel_format_ctor_a8l8 | 0x1001aeac | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a8l8-constructor |
| match | grim_pixel_format_scalar_deleting_destroy_dxt_base | 0x1001aec8 | 28 | 11/11 | 100.00% | 11/11 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- /GX | grim-dxt-base-scalar-deleting-destructor |
| match | grim_pixel_format_ctor_a4l4 | 0x1001aee4 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a4l4-constructor |
| wip | grim_pixel_format_quantize_color_key_dxt | 0x1001af00 | 257 | 56/71 | 17.32% | 2/71 | 0/0/5 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-dxt-color-key-quantization |
| match | grim_pixel_format_ctor_v8u8 | 0x1001b001 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-v8u8-constructor |
| match | grim_pixel_format_ctor_l6v5u5 | 0x1001b01d | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-l6v5u5-constructor |
| match | grim_pixel_format_ctor_x8l8v8u8 | 0x1001b039 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-x8l8v8u8-constructor |
| match | grim_pixel_format_ctor_q8w8v8u8 | 0x1001b055 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-q8w8v8u8-constructor |
| match | grim_pixel_format_ctor_v16u16 | 0x1001b071 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-v16u16-constructor |
| match | grim_pixel_format_ctor_w11v11u10 | 0x1001b08d | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-w11v11u10-constructor |
| match | grim_pixel_format_ctor_a2w10v10u10 | 0x1001b0a9 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-a2w10v10u10-constructor |
| match | grim_pixel_format_ctor_d16_lockable | 0x1001b0c5 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-d16_lockable-constructor |
| match | grim_pixel_format_ctor_l16 | 0x1001b0e1 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-l16-constructor |
| match | grim_pixel_format_ctor_al16 | 0x1001b3a6 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-al16-constructor |
| match | grim_pixel_format_ctor_r16 | 0x1001b3c2 | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-r16-constructor |
| match | grim_pixel_format_ctor_ar16 | 0x1001b3de | 28 | 10/10 | 100.00% | 10/10 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-ar16-constructor |
| match | grim_pixel_format_ctor_dxt1 | 0x1001b3fa | 24 | 8/8 | 100.00% | 8/8 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-dxt1-constructor |
| match | grim_pixel_format_ctor_dxt2 | 0x1001b412 | 24 | 8/8 | 100.00% | 8/8 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-dxt2-constructor |
| match | grim_pixel_format_ctor_dxt3 | 0x1001b42a | 24 | 8/8 | 100.00% | 8/8 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-dxt3-constructor |
| match | grim_pixel_format_ctor_dxt4 | 0x1001b442 | 24 | 8/8 | 100.00% | 8/8 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-dxt4-constructor |
| match | grim_pixel_format_ctor_dxt5 | 0x1001b45a | 24 | 8/8 | 100.00% | 8/8 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-dxt5-constructor |
| match | grim_pixel_format_scalar_deleting_destroy_dxt | 0x1001b472 | 28 | 11/11 | 100.00% | 11/11 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- /GX | grim-dxt-scalar-deleting-destructor |
| match | grim_pixel_format_destroy_yuv | 0x1001b493 | 73 | 23/23 | 100.00% | 23/23 | 6/0/0 | msvc6.5pp /O1 /Oi /G6 /Ob0 /W3 /GR- /GX | grim-yuv-cache-destruction |
| match | grim_pixel_format_ctor_uyvy | 0x1001b4dc | 24 | 8/8 | 100.00% | 8/8 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-uyvy-constructor |
| match | grim_pixel_format_ctor_yuy2 | 0x1001b4f4 | 24 | 8/8 | 100.00% | 8/8 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-pixel-format-yuy2-constructor |
| match | grim_pixel_format_scalar_deleting_destroy_yuv_base | 0x1001bc68 | 28 | 11/11 | 100.00% | 11/11 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /Ob0 /W3 /GR- /GX | grim-yuv-base-scalar-deleting-destructor |
| match | grim_pixel_format_scalar_deleting_destroy_yuv | 0x1001bc84 | 28 | 11/11 | 100.00% | 11/11 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /Ob0 /W3 /GR- /GX | grim-yuv-scalar-deleting-destructor |
| match | grim_dxt_unpremultiply_rgba_block | 0x1002065a | 126 | 55/55 | 100.00% | 55/55 | 0/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-dxt-unpremultiply-rgba-block |
| match | grim_dxt3_decode_block | 0x100219d7 | 131 | 57/57 | 100.00% | 57/57 | 4/0/0 | msvc7.0 /O1 /Oi /G6 /W3 /GR- | grim-dxt3-explicit-alpha-decoder |
| match | grim_dxt2_decode_block | 0x10022114 | 35 | 13/13 | 100.00% | 13/13 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-dxt2-decode-wrapper |
| match | grim_dxt4_decode_block | 0x10022137 | 35 | 13/13 | 100.00% | 13/13 | 2/0/0 | msvc6.5pp /O1 /Oi /G6 /W3 /GR- | grim-dxt4-decode-wrapper |
