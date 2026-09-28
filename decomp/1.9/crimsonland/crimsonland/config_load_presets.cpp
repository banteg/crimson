#include <stdio.h>
#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern int player_name_length;

extern "C" char *game_build_path(char *filename);
FILE *crt_fopen(char *path, char *mode);
int crt_fseek(FILE *fp, long offset, int origin);
long crt_ftell(FILE *fp);
unsigned int crt_fread(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
int crt_fclose(FILE *fp);
extern "C" bool config_sync_from_grim(void);

extern "C" bool config_load_presets(bool skip_grim_settings)
{
    FILE *fp;
    player_input_t *input;
    int player_index;

    input = &player_state_table[0].input;
    input->move_key_forward = 17;
    input->move_key_backward = 31;
    input->turn_key_left = 30;
    input->turn_key_right = 32;
    input->fire_key = 15;
    input->key_reserved_0 = 17;
    input->key_reserved_1 = 31;
    input->aim_key_left = 16;
    input->aim_key_right = 18;

    input = &player_state_table[1].input;
    input->move_key_forward = 200;
    input->move_key_backward = 208;
    input->turn_key_left = 203;
    input->turn_key_right = 205;
    input->fire_key = 157;
    input->key_reserved_0 = 17;
    input->key_reserved_1 = 31;
    input->aim_key_left = 211;
    input->aim_key_right = 201;

    fp = crt_fopen(game_build_path("crimson.cfg"), "rb");
    if (fp == 0) {
        return false;
    }

    crt_fseek(fp, 0, SEEK_END);
    if (crt_ftell(fp) != sizeof(config_blob)) {
        crt_fclose(fp);
        config_sync_from_grim();
        return false;
    }

    crt_fseek(fp, 0, SEEK_SET);
    crt_fread(&config_blob, sizeof(config_blob), 1, fp);
    crt_fclose(fp);

    for (player_index = 0; player_index < 2; ++player_index) {
        player_input_config_t *bindings =
            &config_blob.input_config[player_index];
        int *binding_cursor = &bindings->axis_move_x;
        player_state_table[player_index].input.move_key_forward =
            binding_cursor[-12];
        player_state_table[player_index].input.move_key_backward =
            bindings->move_key_backward;
        player_state_table[player_index].input.turn_key_left =
            bindings->turn_key_left;
        player_state_table[player_index].input.turn_key_right =
            bindings->turn_key_right;
        player_state_table[player_index].input.fire_key =
            bindings->fire_key;
        player_state_table[player_index].input.key_reserved_0 =
            bindings->key_reserved_0;
        player_state_table[player_index].input.key_reserved_1 =
            bindings->key_reserved_1;
        player_state_table[player_index].input.aim_key_left =
            bindings->aim_key_left;
        player_state_table[player_index].input.aim_key_right =
            bindings->aim_key_right;
        player_state_table[player_index].input.axis_aim_y =
            bindings->axis_aim_y;
        player_state_table[player_index].input.axis_aim_x =
            bindings->axis_aim_x;
        player_state_table[player_index].input.axis_move_y =
            bindings->axis_move_y;
        player_state_table[player_index].input.axis_move_x =
            binding_cursor[0];
    }

    grim_interface_ptr->grim_set_config_var(
        0x59,
        config_blob.texture_scale);

    if (!skip_grim_settings) {
        grim_interface_ptr->grim_set_config_var(
            0x54,
            *(bool *)&config_blob.safe_mode_backend_enabled);
        grim_interface_ptr->grim_set_config_var(
            8,
            *(bool *)&config_blob.windowed);
        grim_interface_ptr->grim_set_config_var(
            0x2b,
            (unsigned int)config_blob.display_bpp);
        grim_interface_ptr->grim_set_config_var(
            0x29,
            (unsigned int)config_blob.screen_width);
        grim_interface_ptr->grim_set_config_var(
            0x2a,
            (unsigned int)config_blob.screen_height);
        grim_interface_ptr->grim_set_config_var(
            0x53,
            *(bool *)&config_blob.sound_disabled);
    }

    strcpy(highscore_active_record.player_name, config_blob.player_name);
    player_name_length = config_blob.player_name_length;
    config_blob.highscore_date_mode = 0;
    config_blob.selected_saved_name_slot = 0;
    return true;
}
