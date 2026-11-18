#include "freeware_config.h"
#include "crimsonland_types.h"
#include "grim2d_cpp.h"
#include <stdio.h>

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern freeware_player_t player_state_table[2];
}

extern "C" bool config_load_presets()
{
    unsigned char *first = player_state_table[0].keys;
    unsigned char *second = player_state_table[1].keys;
    first[0] = 17;
    first[1] = 31;
    first[2] = 30;
    first[3] = 32;
    first[4] = 15;
    second[0] = 200;
    second[1] = 208;
    second[2] = 203;
    second[3] = 205;
    second[4] = 157;

    FILE *file = fopen("crimson.cfg", "rb");
    if (!file)
        return false;
    fseek(file, 0, SEEK_END);
    if (ftell(file) != sizeof(config_blob)) {
        fclose(file);
        return false;
    }
    fseek(file, 0, SEEK_SET);
    fread(&config_blob, sizeof(config_blob), 1, file);
    fclose(file);

    first[0] = config_blob.keys[0][0];
    first[1] = config_blob.keys[0][1];
    first[2] = config_blob.keys[0][2];
    first[3] = config_blob.keys[0][3];
    first[4] = config_blob.keys[0][4];
    second[0] = config_blob.keys[1][0];
    second[1] = config_blob.keys[1][1];
    second[2] = config_blob.keys[1][2];
    second[3] = config_blob.keys[1][3];
    second[4] = config_blob.keys[1][4];

    grim_interface_ptr->grim_set_config_var(6, config_blob.windowed);
    grim_interface_ptr->grim_set_config_var(9, (unsigned int)config_blob.display_bpp);
    grim_interface_ptr->grim_set_config_var(7, (unsigned int)config_blob.screen_width);
    grim_interface_ptr->grim_set_config_var(8, (unsigned int)config_blob.screen_height);
#if CL_BUILD >= 10400
    grim_interface_ptr->grim_set_config_var(0x54, config_blob.safe_mode);
    grim_interface_ptr->grim_set_config_var(0x53, config_blob.audio_disabled);
#endif
    return true;
}
