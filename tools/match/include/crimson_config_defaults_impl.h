#include <stddef.h>

#ifndef CRIMSON_CONFIG_DEFAULTS_FUNCTION
#error "define CRIMSON_CONFIG_DEFAULTS_FUNCTION before including this file"
#endif

#ifndef CRIMSON_CONFIG_DEFAULTS_BLOB
#error "define CRIMSON_CONFIG_DEFAULTS_BLOB before including this file"
#endif

extern "C" void CRIMSON_CONFIG_DEFAULTS_FUNCTION(void)
{
    int i;
    int saved_order_offset;

    CRIMSON_CONFIG_DEFAULTS_BLOB.hardcore = 0;
    memset(
        &CRIMSON_CONFIG_DEFAULTS_BLOB.ui_info_texts,
        1,
        sizeof(CRIMSON_CONFIG_DEFAULTS_BLOB.ui_info_texts));
    CRIMSON_CONFIG_DEFAULTS_BLOB.perk_prompt_counter = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.mouse_sensitivity = 0.5f;
    *(int *)&CRIMSON_CONFIG_DEFAULTS_BLOB.reserved6_450[0] = 1;
    CRIMSON_CONFIG_DEFAULTS_BLOB.key_pick_perk = 0x101;
    CRIMSON_CONFIG_DEFAULTS_BLOB.key_reload = 0x102;
    CRIMSON_CONFIG_DEFAULTS_BLOB.safe_mode_backend_enabled = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.texture_scale = 1.0f;
    CRIMSON_CONFIG_DEFAULTS_BLOB.score_load_gate = 0;
    memset(CRIMSON_CONFIG_DEFAULTS_BLOB.player_name_buf, 0, 9);

    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    do {
        *(int *)((char *)&CRIMSON_CONFIG_DEFAULTS_BLOB + saved_order_offset) = i;
        strcpy(CRIMSON_CONFIG_DEFAULTS_BLOB.saved_names[i], "default");
        saved_order_offset += sizeof(int);
        ++i;
    } while (saved_order_offset < (int)offsetof(crimson_cfg_t, saved_names));

    CRIMSON_CONFIG_DEFAULTS_BLOB.highscore_duplicate_mode = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.highscore_date_mode = 0;
    memset(
        CRIMSON_CONFIG_DEFAULTS_BLOB.player_name,
        0,
        sizeof(CRIMSON_CONFIG_DEFAULTS_BLOB.player_name));
    strcpy(CRIMSON_CONFIG_DEFAULTS_BLOB.player_name, "10tons");
    CRIMSON_CONFIG_DEFAULTS_BLOB.saved_name_count = 1;
    CRIMSON_CONFIG_DEFAULTS_BLOB.selected_saved_name_slot = 0;

    CRIMSON_CONFIG_DEFAULTS_BLOB.sound_disabled = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.music_disabled = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.violence_disabled = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.sound_frequency_adjustment = 1;
    *(int *)&CRIMSON_CONFIG_DEFAULTS_BLOB.reserved1_1a4[4] = 0;
    *(int *)&CRIMSON_CONFIG_DEFAULTS_BLOB.reserved1_1a4[8] = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.reserved0_6c = 0;

    CRIMSON_CONFIG_DEFAULTS_BLOB.display_bpp = 32;
    CRIMSON_CONFIG_DEFAULTS_BLOB.windowed = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.game_mode = GAME_MODE_SURVIVAL;
    CRIMSON_CONFIG_DEFAULTS_BLOB.fx_detail_flag0 = 1;
    CRIMSON_CONFIG_DEFAULTS_BLOB.reserved0_0f = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.fx_detail_flag1 = 1;
    CRIMSON_CONFIG_DEFAULTS_BLOB.movement_schemes[0] = 2;
    CRIMSON_CONFIG_DEFAULTS_BLOB.movement_schemes[1] = 2;
    CRIMSON_CONFIG_DEFAULTS_BLOB.aim_schemes[0] = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.aim_schemes[1] = 0;
    CRIMSON_CONFIG_DEFAULTS_BLOB.fx_detail_flag2 = 1;
    CRIMSON_CONFIG_DEFAULTS_BLOB.player_count = 1;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].turn_key_right = 32;
    CRIMSON_CONFIG_DEFAULTS_BLOB.detail_preset = 5;

    CRIMSON_CONFIG_DEFAULTS_BLOB.aim_pov_right = 9000;
    CRIMSON_CONFIG_DEFAULTS_BLOB.aim_pov_left = 27000;
    *(int *)&CRIMSON_CONFIG_DEFAULTS_BLOB.reserved1_1a4[0] = 100;
    CRIMSON_CONFIG_DEFAULTS_BLOB.screen_width = 800;
    CRIMSON_CONFIG_DEFAULTS_BLOB.screen_height = 600;
    CRIMSON_CONFIG_DEFAULTS_BLOB.sfx_volume = 1.0f;
    CRIMSON_CONFIG_DEFAULTS_BLOB.music_volume = 1.0f;

    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].move_key_forward = 17;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].move_key_backward = 31;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].turn_key_left = 30;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].fire_key = 256;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].key_reserved_0 = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].key_reserved_1 = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].aim_key_left = 16;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].aim_key_right = 18;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].axis_aim_y = 319;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].axis_aim_x = 320;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].axis_move_y = 321;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].axis_move_x = 339;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].reserved[0] = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].reserved[1] = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[0].reserved[2] = 382;

    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].move_key_forward = 200;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].move_key_backward = 208;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].turn_key_left = 203;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].turn_key_right = 205;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].fire_key = 157;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].key_reserved_0 = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].key_reserved_1 = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].aim_key_left = 211;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].aim_key_right = 209;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].axis_aim_y = 319;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].axis_aim_x = 320;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].axis_move_y = 321;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].axis_move_x = 339;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].reserved[0] = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].reserved[1] = 382;
    CRIMSON_CONFIG_DEFAULTS_BLOB.input_config[1].reserved[2] = 382;

    *(unsigned short *)CRIMSON_CONFIG_DEFAULTS_BLOB.direction_arrow_flags =
        0x101;
}

#undef CRIMSON_CONFIG_DEFAULTS_BLOB
#undef CRIMSON_CONFIG_DEFAULTS_FUNCTION
