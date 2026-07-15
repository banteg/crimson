#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" void config_init_defaults(void)
{
    int i;
    char *saved_name;

    memset(config_blob.player_name_buf, 0, 9);
    config_blob.hardcore = 0;
    config_blob.ui_info_texts = 1;
    config_blob.perk_prompt_counter = 0;
    config_blob.mouse_sensitivity = 0.5f;
    *(int *)&config_blob.reserved6_450[0] = 1;
    config_blob.key_pick_perk = 0x101;
    config_blob.key_reload = 0x102;
    config_blob.safe_mode_backend_enabled = 0;
    config_blob.texture_scale = 1.0f;
    config_blob.score_load_gate = 0;

    saved_name = config_blob.saved_names[0];
    for (i = 0; i < 8; ++i) {
        config_blob.saved_name_order[i] = i;
        strcpy(saved_name, "default");
        saved_name += sizeof(config_blob.saved_names[0]);
    }

    config_blob.highscore_duplicate_mode = 0;
    config_blob.highscore_date_mode = 0;
    memset(config_blob.player_name, 0, sizeof(config_blob.player_name));
    strcpy(config_blob.player_name, "10tons");
    config_blob.saved_name_count = 1;
    config_blob.selected_saved_name_slot = 0;

    config_blob.sound_disabled = 0;
    config_blob.music_disabled = 0;
    config_blob.violence_disabled = 0;
    config_blob.sound_frequency_adjustment = 1;
    *(int *)&config_blob.reserved1_1a4[4] = 0;
    *(int *)&config_blob.reserved1_1a4[8] = 0;
    *(int *)&config_blob.reserved0_48[0x24] = 0;

    config_blob.display_bpp = 32;
    config_blob.windowed = 0;
    config_blob.game_mode = GAME_MODE_SURVIVAL;
    config_blob.fx_detail_flag0 = 1;
    config_blob.reserved0_0f = 0;
    config_blob.fx_detail_flag1 = 1;
    config_blob.player_mode_flags = 2;
    *(int *)&config_blob.reserved0_20[0] = 2;
    config_blob.aim_scheme = 0;
    *(int *)&config_blob.reserved0_48[0] = 0;
    config_blob.fx_detail_flag2 = 1;
    config_blob.player_count = 1;
    config_blob.keybinds_p1[3] = 32;
    config_blob.detail_preset = 5;

    config_blob.aim_pov_right = 9000;
    config_blob.aim_pov_left = 27000;
    *(int *)&config_blob.reserved1_1a4[0] = 100;
    config_blob.screen_width = 800;
    config_blob.screen_height = 600;
    config_blob.sfx_volume = 1.0f;
    config_blob.music_volume = 1.0f;

    config_blob.keybinds_p1[0] = 17;
    config_blob.keybinds_p1[1] = 31;
    config_blob.keybinds_p1[2] = 30;
    config_blob.keybinds_p1[4] = 256;
    config_blob.keybinds_p1[5] = 382;
    config_blob.keybinds_p1[6] = 382;
    config_blob.keybinds_p1[7] = 16;
    config_blob.keybinds_p1[8] = 18;
    config_blob.keybinds_p1[9] = 319;
    config_blob.keybinds_p1[10] = 320;
    config_blob.keybinds_p1[11] = 321;
    config_blob.keybinds_p1[12] = 339;
    *(int *)&config_blob.reserved2[0] = 382;
    *(int *)&config_blob.reserved2[4] = 382;
    *(int *)&config_blob.reserved2[8] = 382;

    config_blob.keybinds_p2[0] = 200;
    config_blob.keybinds_p2[1] = 208;
    config_blob.keybinds_p2[2] = 203;
    config_blob.keybinds_p2[3] = 205;
    config_blob.keybinds_p2[4] = 157;
    config_blob.keybinds_p2[5] = 382;
    config_blob.keybinds_p2[6] = 382;
    config_blob.keybinds_p2[7] = 211;
    config_blob.keybinds_p2[8] = 209;
    config_blob.keybinds_p2[9] = 319;
    config_blob.keybinds_p2[10] = 320;
    config_blob.keybinds_p2[11] = 321;
    config_blob.keybinds_p2[12] = 339;
    *(int *)&config_blob.reserved3[0] = 382;
    *(int *)&config_blob.reserved3[4] = 382;
    *(int *)&config_blob.reserved3[8] = 382;

    *(unsigned short *)config_blob.direction_arrow_flags = 0x101;
}
