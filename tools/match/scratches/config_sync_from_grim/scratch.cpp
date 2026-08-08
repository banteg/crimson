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
        defaults.level_up_count = 0;
        defaults.mouse_sensitivity = 0.5f;
        defaults.ten_tons_logging_completed = 1;
        defaults.key_pick_perk = 0x101;
        defaults.key_reload = 0x102;
        defaults.safe_mode_backend_enabled = 0;
        defaults.texture_scale = 1.0f;
        defaults.show_online_scores = 0;
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
        defaults.shadows_enabled = 1;
        defaults.flame_glow_enabled = 1;
        defaults.smoke_enabled = 1;
        defaults.player_count = 1;
        defaults.input_config[0].turn_key_right = 32;
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
        defaults.config_for = 0;
        defaults.screen_width = 800;
        defaults.screen_height = 600;
        defaults.windowed = 0;
        defaults.sharp_ground_enabled = 0;
        defaults.movement_schemes[0] = 2;
        defaults.movement_schemes[1] = 2;
        defaults.aim_schemes[0] = 0;
        defaults.aim_schemes[1] = 0;
        defaults.sfx_volume = 1.0f;
        defaults.music_volume = 1.0f;

        defaults.input_config[0].move_key_forward = 17;
        defaults.input_config[0].move_key_backward = 31;
        defaults.input_config[0].turn_key_left = 30;
        defaults.input_config[0].fire_key = 256;
        defaults.input_config[0].key_reserved_0 = 382;
        defaults.input_config[0].key_reserved_1 = 382;
        defaults.input_config[0].aim_key_left = 16;
        defaults.input_config[0].aim_key_right = 18;
        defaults.input_config[0].axis_aim_y = 319;
        defaults.input_config[0].axis_aim_x = 320;
        defaults.input_config[0].axis_move_y = 321;
        defaults.input_config[0].axis_move_x = 339;
        defaults.input_config[0].reserved[0] = 382;
        defaults.input_config[0].reserved[1] = 382;
        defaults.input_config[0].reserved[2] = 382;

        defaults.input_config[1].move_key_forward = 200;
        defaults.input_config[1].move_key_backward = 208;
        defaults.input_config[1].turn_key_left = 203;
        defaults.input_config[1].turn_key_right = 205;
        defaults.input_config[1].fire_key = 157;
        defaults.input_config[1].key_reserved_0 = 382;
        defaults.input_config[1].key_reserved_1 = 382;
        defaults.input_config[1].aim_key_left = 211;
        defaults.input_config[1].aim_key_right = 209;
        defaults.input_config[1].axis_aim_y = 319;
        defaults.input_config[1].axis_aim_x = 320;
        defaults.input_config[1].axis_move_y = 321;
        defaults.input_config[1].axis_move_x = 339;
        defaults.input_config[1].reserved[0] = 382;
        defaults.input_config[1].reserved[1] = 382;
        defaults.input_config[1].reserved[2] = 382;

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
