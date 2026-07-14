#include <string.h>

#include "crimsonland_resource.h"

unsigned char resource_pack_set(char *path)
{
    FILE *fp = fopen(path, "rb");

    if (fp == 0) {
        resource_pack_path_buf[0] = 0;
        resource_pack_enabled = 0;
        return 0;
    }

    strcpy(resource_pack_path_buf, path);
    resource_pack_enabled = 1;
    fclose(fp);
    return 1;
}
