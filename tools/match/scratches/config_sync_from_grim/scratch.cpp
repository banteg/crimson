#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct FILE;

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" int player_name_length;
extern "C" unsigned char grim_config_invoked;

extern "C" char *game_build_path(char *filename);
extern "C" FILE *crt_fopen(char *path, char *mode);
extern "C" int crt_fseek(FILE *fp, long offset, int origin);
extern "C" long crt_ftell(FILE *fp);
extern "C" unsigned int crt_fread(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
extern "C" unsigned int crt_fwrite(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
extern "C" int crt_fclose(FILE *fp);

extern "C" bool config_sync_from_grim(void)
{
    crimson_cfg_t defaults;
    FILE *fp;
    int i;

    config_blob.windowed = grim_interface_ptr->grim_get_config_var(8);
    config_blob.display_bpp =
        grim_interface_ptr->grim_get_config_var(0x2b).words[0];
    config_blob.screen_width =
        grim_interface_ptr->grim_get_config_var(0x29).words[0];
    config_blob.screen_height =
        grim_interface_ptr->grim_get_config_var(0x2a).words[0];
    *(unsigned int *)&config_blob.texture_scale =
        grim_interface_ptr->grim_get_config_var(0x59).words[0];
    config_blob.safe_mode_backend_enabled =
        grim_interface_ptr->grim_get_config_var(0x54);

    strcpy(config_blob.player_name, highscore_active_record.player_name);
    config_blob.player_name_length = player_name_length;

    if (grim_config_invoked) {
        defaults.hardcore = 0;
        defaults.ui_info_texts = 1;
        defaults.perk_prompt_counter = 0;
        defaults.mouse_sensitivity = 0.5f;
        *(int *)&defaults.reserved6_450[0] = 1;
        defaults.key_pick_perk = 0x101;
        defaults.key_reload = 0x102;
        defaults.safe_mode_backend_enabled = 0;
        defaults.texture_scale = 1.0f;
        defaults.score_load_gate = 0;
        memset(defaults.player_name_buf, 0, 9);

        for (i = 0; i < 8; ++i) {
            defaults.saved_name_order[i] = i;
            strcpy(defaults.saved_names[i], "default");
        }

        defaults.highscore_duplicate_mode = 0;
        defaults.highscore_date_mode = 0;
        memset(defaults.player_name, 0, sizeof(defaults.player_name));
        strcpy(defaults.player_name, "10tons");
        defaults.saved_name_count = 1;
        defaults.sound_frequency_adjustment = 1;
        defaults.display_bpp = 32;
        defaults.game_mode = GAME_MODE_SURVIVAL;
        defaults.fx_detail_flag0 = 1;
        defaults.fx_detail_flag1 = 1;
        defaults.fx_detail_flag2 = 1;
        defaults.player_count = 1;
        defaults.keybinds_p1[3] = 32;
        defaults.selected_saved_name_slot = 0;
        defaults.detail_preset = 5;
        defaults.sound_disabled = 0;
        defaults.music_disabled = 0;
        defaults.violence_disabled = 0;
        *(int *)&defaults.reserved1_1a4[4] = 0;
        *(int *)&defaults.reserved1_1a4[8] = 0;
        defaults.aim_pov_right = 9000;
        defaults.aim_pov_left = 27000;
        *(int *)&defaults.reserved1_1a4[0] = 100;
        *(int *)&defaults.reserved0_48[0x24] = 0;
        defaults.screen_width = 800;
        defaults.screen_height = 600;
        defaults.windowed = 0;
        defaults.reserved0_0f = 0;
        defaults.player_mode_flags = 2;
        *(int *)&defaults.reserved0_20[0] = 2;
        defaults.aim_scheme = 0;
        *(int *)&defaults.reserved0_48[0] = 0;
        defaults.sfx_volume = 1.0f;
        defaults.music_volume = 1.0f;

        defaults.keybinds_p1[0] = 17;
        defaults.keybinds_p1[1] = 31;
        defaults.keybinds_p1[2] = 30;
        defaults.keybinds_p1[4] = 256;
        defaults.keybinds_p1[5] = 382;
        defaults.keybinds_p1[6] = 382;
        defaults.keybinds_p1[7] = 16;
        defaults.keybinds_p1[8] = 18;
        defaults.keybinds_p1[9] = 319;
        defaults.keybinds_p1[10] = 320;
        defaults.keybinds_p1[11] = 321;
        defaults.keybinds_p1[12] = 339;
        *(int *)&defaults.reserved2[0] = 382;
        *(int *)&defaults.reserved2[4] = 382;
        *(int *)&defaults.reserved2[8] = 382;

        defaults.keybinds_p2[0] = 200;
        defaults.keybinds_p2[1] = 208;
        defaults.keybinds_p2[2] = 203;
        defaults.keybinds_p2[3] = 205;
        defaults.keybinds_p2[4] = 157;
        defaults.keybinds_p2[5] = 382;
        defaults.keybinds_p2[6] = 382;
        defaults.keybinds_p2[7] = 211;
        defaults.keybinds_p2[8] = 209;
        defaults.keybinds_p2[9] = 319;
        defaults.keybinds_p2[10] = 320;
        defaults.keybinds_p2[11] = 321;
        defaults.keybinds_p2[12] = 339;
        *(int *)&defaults.reserved3[0] = 382;
        *(int *)&defaults.reserved3[4] = 382;
        *(int *)&defaults.reserved3[8] = 382;

        *(unsigned short *)defaults.direction_arrow_flags = 0x101;

        fp = crt_fopen(game_build_path("crimson.cfg"), "rb");
        if (fp != 0) {
            crt_fseek(fp, 0, 2);
            if (crt_ftell(fp) == sizeof(defaults)) {
                crt_fseek(fp, 0, 0);
                crt_fread(&defaults, sizeof(defaults), 1, fp);
                config_blob.violence_disabled = defaults.violence_disabled;
                strcpy(config_blob.player_name_buf, defaults.player_name_buf);
            }
            crt_fclose(fp);
        }
    }

    fp = crt_fopen(game_build_path("crimson.cfg"), "wb");
    if (fp != 0) {
        crt_fwrite(&config_blob, sizeof(config_blob), 1, fp);
        crt_fclose(fp);
    }
    return true;
}
