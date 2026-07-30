#include <stddef.h>
#include <string.h>

#include "crimsonland_gameplay.h"

extern crimson_cfg_t grim_config_blob;

#ifndef CRIMSON_SAVED_NAME_SCHEDULE
#define CRIMSON_SAVED_NAME_SCHEDULE 0
#endif

extern "C" void grim_config_defaults_init(void)
{
    int i;
    int saved_order_offset;
#if CRIMSON_SAVED_NAME_SCHEDULE >= 1 && CRIMSON_SAVED_NAME_SCHEDULE <= 3
    char *saved_name;
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 4 && CRIMSON_SAVED_NAME_SCHEDULE <= 7
    char (*saved_name)[27];
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 8 && CRIMSON_SAVED_NAME_SCHEDULE <= 9
    char *saved_name;
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 11 && CRIMSON_SAVED_NAME_SCHEDULE <= 15
    char (*saved_names)[27];
#elif CRIMSON_SAVED_NAME_SCHEDULE == 16
    char (&saved_names)[8][27] = grim_config_blob.saved_names;
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 17 && CRIMSON_SAVED_NAME_SCHEDULE <= 20
    char *saved_names;
#endif

    grim_config_blob.hardcore = 0;
    memset(
        &grim_config_blob.ui_info_texts,
        1,
        sizeof(grim_config_blob.ui_info_texts));
    grim_config_blob.perk_prompt_counter = 0;
    grim_config_blob.mouse_sensitivity = 0.5f;
    *(int *)&grim_config_blob.reserved6_450[0] = 1;
    grim_config_blob.key_pick_perk = 0x101;
    grim_config_blob.key_reload = 0x102;
    grim_config_blob.safe_mode_backend_enabled = 0;
    grim_config_blob.texture_scale = 1.0f;
    grim_config_blob.score_load_gate = 0;
    memset(grim_config_blob.player_name_buf, 0, 9);

#if CRIMSON_SAVED_NAME_SCHEDULE == 1
    saved_name = grim_config_blob.saved_names[0];
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 2
    i = 0;
    saved_name = grim_config_blob.saved_names[0];
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 3
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    saved_name = grim_config_blob.saved_names[0];
#elif CRIMSON_SAVED_NAME_SCHEDULE == 4
    saved_name = grim_config_blob.saved_names;
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 5
    i = 0;
    saved_name = grim_config_blob.saved_names;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 6 || CRIMSON_SAVED_NAME_SCHEDULE == 7
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    saved_name = grim_config_blob.saved_names;
#elif CRIMSON_SAVED_NAME_SCHEDULE == 8
    saved_name = &grim_config_blob.saved_names[0][0];
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    i = 0;
#elif CRIMSON_SAVED_NAME_SCHEDULE == 9
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    saved_name = &grim_config_blob.saved_names[0][0];
    i = 0;
#elif CRIMSON_SAVED_NAME_SCHEDULE == 10
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    i = 0;
#elif CRIMSON_SAVED_NAME_SCHEDULE == 11
    saved_names = grim_config_blob.saved_names;
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 12
    i = 0;
    saved_names = grim_config_blob.saved_names;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 13
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    saved_names = grim_config_blob.saved_names;
#elif CRIMSON_SAVED_NAME_SCHEDULE == 14
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    saved_names = grim_config_blob.saved_names;
    i = 0;
#elif CRIMSON_SAVED_NAME_SCHEDULE == 15
    saved_names = grim_config_blob.saved_names;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    i = 0;
#elif CRIMSON_SAVED_NAME_SCHEDULE == 16
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 17
    saved_names = &grim_config_blob.saved_names[0][0];
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 18
    i = 0;
    saved_names = &grim_config_blob.saved_names[0][0];
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#elif CRIMSON_SAVED_NAME_SCHEDULE == 19
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    saved_names = &grim_config_blob.saved_names[0][0];
#elif CRIMSON_SAVED_NAME_SCHEDULE == 20
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
    saved_names = &grim_config_blob.saved_names[0][0];
    i = 0;
#else
    i = 0;
    saved_order_offset = offsetof(crimson_cfg_t, saved_name_order);
#endif
    do {
        *(int *)((char *)&grim_config_blob + saved_order_offset) = i;
#if CRIMSON_SAVED_NAME_SCHEDULE >= 1 && CRIMSON_SAVED_NAME_SCHEDULE <= 3
        strcpy(saved_name, "default");
        saved_name += sizeof(grim_config_blob.saved_names[0]);
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 4 && CRIMSON_SAVED_NAME_SCHEDULE <= 6
        strcpy(*saved_name++, "default");
#elif CRIMSON_SAVED_NAME_SCHEDULE == 7
        strcpy(*saved_name, "default");
        ++saved_name;
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 8 && CRIMSON_SAVED_NAME_SCHEDULE <= 9
        strcpy(saved_name, "default");
        saved_name += sizeof(grim_config_blob.saved_names[0]);
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 11 && CRIMSON_SAVED_NAME_SCHEDULE <= 16
        strcpy(saved_names[i], "default");
#elif CRIMSON_SAVED_NAME_SCHEDULE >= 17 && CRIMSON_SAVED_NAME_SCHEDULE <= 20
        strcpy(
            saved_names + i * sizeof(grim_config_blob.saved_names[0]),
            "default");
#else
        strcpy(grim_config_blob.saved_names[i], "default");
#endif
        saved_order_offset += sizeof(int);
        ++i;
    } while (saved_order_offset < (int)offsetof(crimson_cfg_t, saved_names));

    grim_config_blob.highscore_duplicate_mode = 0;
    grim_config_blob.highscore_date_mode = 0;
    memset(
        grim_config_blob.player_name,
        0,
        sizeof(grim_config_blob.player_name));
    strcpy(grim_config_blob.player_name, "10tons");
    grim_config_blob.saved_name_count = 1;
    grim_config_blob.selected_saved_name_slot = 0;

    grim_config_blob.sound_disabled = 0;
    grim_config_blob.music_disabled = 0;
    grim_config_blob.violence_disabled = 0;
    grim_config_blob.sound_frequency_adjustment = 1;
    *(int *)&grim_config_blob.reserved1_1a4[4] = 0;
    *(int *)&grim_config_blob.reserved1_1a4[8] = 0;
    grim_config_blob.reserved0_6c = 0;

    grim_config_blob.display_bpp = 32;
    grim_config_blob.windowed = 0;
    grim_config_blob.game_mode = GAME_MODE_SURVIVAL;
    grim_config_blob.fx_detail_flag0 = 1;
    grim_config_blob.reserved0_0f = 0;
    grim_config_blob.fx_detail_flag1 = 1;
    grim_config_blob.movement_schemes[0] = 2;
    grim_config_blob.movement_schemes[1] = 2;
    grim_config_blob.aim_schemes[0] = 0;
    grim_config_blob.aim_schemes[1] = 0;
    grim_config_blob.fx_detail_flag2 = 1;
    grim_config_blob.player_count = 1;
    grim_config_blob.input_config[0].turn_key_right = 32;
    grim_config_blob.detail_preset = 5;

    grim_config_blob.aim_pov_right = 9000;
    grim_config_blob.aim_pov_left = 27000;
    *(int *)&grim_config_blob.reserved1_1a4[0] = 100;
    grim_config_blob.screen_width = 800;
    grim_config_blob.screen_height = 600;
    grim_config_blob.sfx_volume = 1.0f;
    grim_config_blob.music_volume = 1.0f;

    grim_config_blob.input_config[0].move_key_forward = 17;
    grim_config_blob.input_config[0].move_key_backward = 31;
    grim_config_blob.input_config[0].turn_key_left = 30;
    grim_config_blob.input_config[0].fire_key = 256;
    grim_config_blob.input_config[0].key_reserved_0 = 382;
    grim_config_blob.input_config[0].key_reserved_1 = 382;
    grim_config_blob.input_config[0].aim_key_left = 16;
    grim_config_blob.input_config[0].aim_key_right = 18;
    grim_config_blob.input_config[0].axis_aim_y = 319;
    grim_config_blob.input_config[0].axis_aim_x = 320;
    grim_config_blob.input_config[0].axis_move_y = 321;
    grim_config_blob.input_config[0].axis_move_x = 339;
    grim_config_blob.input_config[0].reserved[0] = 382;
    grim_config_blob.input_config[0].reserved[1] = 382;
    grim_config_blob.input_config[0].reserved[2] = 382;

    grim_config_blob.input_config[1].move_key_forward = 200;
    grim_config_blob.input_config[1].move_key_backward = 208;
    grim_config_blob.input_config[1].turn_key_left = 203;
    grim_config_blob.input_config[1].turn_key_right = 205;
    grim_config_blob.input_config[1].fire_key = 157;
    grim_config_blob.input_config[1].key_reserved_0 = 382;
    grim_config_blob.input_config[1].key_reserved_1 = 382;
    grim_config_blob.input_config[1].aim_key_left = 211;
    grim_config_blob.input_config[1].aim_key_right = 209;
    grim_config_blob.input_config[1].axis_aim_y = 319;
    grim_config_blob.input_config[1].axis_aim_x = 320;
    grim_config_blob.input_config[1].axis_move_y = 321;
    grim_config_blob.input_config[1].axis_move_x = 339;
    grim_config_blob.input_config[1].reserved[0] = 382;
    grim_config_blob.input_config[1].reserved[1] = 382;
    grim_config_blob.input_config[1].reserved[2] = 382;

    *(unsigned short *)grim_config_blob.direction_arrow_flags = 0x101;
}
