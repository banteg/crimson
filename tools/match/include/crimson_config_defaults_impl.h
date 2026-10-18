#ifndef CRIMSON_CONFIG_DEFAULTS_IMPL_H
#define CRIMSON_CONFIG_DEFAULTS_IMPL_H

#include <string.h>

#include "crimsonland_gameplay.h"

// The shared default configuration, the game's C++ reset of a config blob
// inlined through `this`: Grim's grim_config_defaults_init, the game's
// config_init_defaults and, in 1.9.8, config_sync_from_grim's local legacy blob.
// `this` stays opaque through loop optimization, so the plain indexed saved-name
// loop keeps native's order-slot pointer and, under C2 9044, the
// `this - "default" + 0xa8` copy delta; a direct blob reference folds the field
// offsets first.
struct crimson_cfg_cpp_t : crimson_cfg_t {
    void set_defaults()
    {
        int i;

        hardcore = 0;
        // Code-generation guard: 1.9.8 stores the flag directly; 1.9.93's
        // grim and game copies keep the one-byte memset's register order.
#if CL_BUILD == 10908
        ui_info_texts = 1;
#else
        memset(&ui_info_texts, 1, sizeof(ui_info_texts));
#endif
        level_up_count = 0;
        mouse_sensitivity = 0.5f;
        ten_tons_logging_completed = 1;
        key_pick_perk = 0x101;
        key_reload = 0x102;
        safe_mode_backend_enabled = 0;
        texture_scale = 1.0f;
        show_online_scores = 0;
        memset(player_name_buf, 0, 9);

        for (i = 0; i < 8; ++i) {
            saved_name_order[i] = i;
            strcpy(saved_names[i], "default");
        }

        highscore_duplicate_mode = 0;
        highscore_date_mode = 0;
        memset(player_name, 0, sizeof(player_name));
        strcpy(player_name, "10tons");
        saved_name_count = 1;
        selected_saved_name_slot = 0;
        detail_preset = 5;

        sound_disabled = 0;
        music_disabled = 0;
        violence_disabled = 0;
        sound_frequency_adjustment = 1;
        *(int *)&reserved1_1a4[4] = 0;
        *(int *)&reserved1_1a4[8] = 0;
        aim_pov_right = 9000;
        aim_pov_left = 27000;
        *(int *)&reserved1_1a4[0] = 100;
        config_for = 0;
        screen_width = 800;
        screen_height = 600;

        display_bpp = 32;
        windowed = 0;
        game_mode = GAME_MODE_SURVIVAL;
        shadows_enabled = 1;
        sharp_ground_enabled = 0;
        flame_glow_enabled = 1;
        movement_schemes[0] = 2;
        movement_schemes[1] = 2;
        aim_schemes[0] = 0;
        aim_schemes[1] = 0;
        smoke_enabled = 1;
        player_count = 1;
        input_config[0].turn_key_right = 32;

        sfx_volume = 1.0f;
        music_volume = 1.0f;

        input_config[0].move_key_forward = 17;
        input_config[0].move_key_backward = 31;
        input_config[0].turn_key_left = 30;
        input_config[0].fire_key = 256;
        input_config[0].key_reserved_0 = 382;
        input_config[0].key_reserved_1 = 382;
        input_config[0].aim_key_left = 16;
        input_config[0].aim_key_right = 18;
        input_config[0].axis_aim_y = 319;
        input_config[0].axis_aim_x = 320;
        input_config[0].axis_move_y = 321;
        input_config[0].axis_move_x = 339;
        input_config[0].reserved[0] = 382;
        input_config[0].reserved[1] = 382;
        input_config[0].reserved[2] = 382;

        input_config[1].move_key_forward = 200;
        input_config[1].move_key_backward = 208;
        input_config[1].turn_key_left = 203;
        input_config[1].turn_key_right = 205;
        input_config[1].fire_key = 157;
        input_config[1].key_reserved_0 = 382;
        input_config[1].key_reserved_1 = 382;
        input_config[1].aim_key_left = 211;
        input_config[1].aim_key_right = 209;
        input_config[1].axis_aim_y = 319;
        input_config[1].axis_aim_x = 320;
        input_config[1].axis_move_y = 321;
        input_config[1].axis_move_x = 339;
        input_config[1].reserved[0] = 382;
        input_config[1].reserved[1] = 382;
        input_config[1].reserved[2] = 382;

        memset(direction_arrow_flags, 1, 2);
    }
};

#endif
