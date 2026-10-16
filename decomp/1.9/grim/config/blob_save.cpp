#include <stdio.h>

#include "crimsonland_gameplay.h"

extern crimson_cfg_t grim_config_blob;

bool grim_config_blob_save(void)
{
    FILE *file = fopen("crimson.cfg", "wb");
    if (file != 0) {
        fwrite(&grim_config_blob, sizeof(grim_config_blob), 1, file);
        fclose(file);
    }
    return true;
}
