#include <string.h>

#include "crimsonland_resource.h"

unsigned char resource_open_read(char *path, unsigned int *size_out)
{
    if (resource_pack_enabled) {
        FILE *fp;

        resource_fp = fopen(resource_pack_path_buf, "rb");
        if (resource_fp == 0) {
            return 0;
        }

        fp = resource_fp;
        fseek(fp, 4, SEEK_SET);
        while (resource_pack_read_cstring(fp)) {
            unsigned int entry_size;

            fread(&entry_size, sizeof(entry_size), 1, fp);
            *size_out = entry_size;
            if (_stricmp(resource_pack_entry_name_buf, path) == 0) {
                return 1;
            }
            fseek(fp, entry_size, SEEK_CUR);
        }
        fclose(fp);
    }

    resource_fp = fopen(path, "rb");
    if (resource_fp == 0) {
        return 0;
    }
    fseek(resource_fp, 0, SEEK_END);
    *size_out = ftell(resource_fp);
    fseek(resource_fp, 0, SEEK_SET);
    return 1;
}
