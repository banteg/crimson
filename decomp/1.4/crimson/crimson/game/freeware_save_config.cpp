#include "freeware_config.h"
#include "grim2d_cpp.h"
#include <stdio.h>

extern "C" IGrim2D_cpp *grim_interface_ptr;

extern "C" bool freeware_save_config()
{
    config_blob.windowed = grim_interface_ptr->grim_get_config_var(6);
    config_blob.display_bpp = grim_interface_ptr->grim_get_config_var(9).words[0];
    config_blob.screen_width = grim_interface_ptr->grim_get_config_var(7).words[0];
    config_blob.screen_height = grim_interface_ptr->grim_get_config_var(8).words[0];

    FILE *file = fopen("crimson.cfg", "wb");
    if (!file)
        return false;
    fwrite(&config_blob, sizeof(config_blob), 1, file);
    fclose(file);
    return true;
}
