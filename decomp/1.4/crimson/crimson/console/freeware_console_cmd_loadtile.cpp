#include <stdio.h>
#include <string.h>

#include "crimsonland_console.h"
#include "crimsonland_resource.h"
#include "../level/freeware_editor_brush.h"

#pragma pack(push, 1)
struct freeware_tile_header_t {
    unsigned char image_info[12];
    unsigned short width;
    unsigned short height;
    unsigned char bits_per_pixel;
    unsigned char descriptor;
};
#pragma pack(pop)

extern "C" {
extern freeware_tile_header_t freeware_tile_header;
int console_cmd_argc_get(void);
bool texture_get_or_load(char *name, char *path);
}

namespace {
const int resource_pack_path = 0x10;
}

void freeware_console_cmd_loadtile(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "loadtile <tilefileid>\n");
        return;
    }

    FILE *file = fopen((char *)grim_interface_ptr->grim_get_config_var(resource_pack_path).words[3], "rb");
    if (!file) {
        console_printf(&console_log_queue, "Could not open file '%s'\n",
                       (char *)grim_interface_ptr->grim_get_config_var(resource_pack_path).words[3]);
        return;
    }

    fseek(file, 4, SEEK_SET);
    while (resource_pack_read_cstring(file)) {
        unsigned int entry_size;
        fread(&entry_size, sizeof(entry_size), 1, file);
        fread(&freeware_tile_header, sizeof(freeware_tile_header), 1, file);
        if (strcmp(resource_pack_entry_name_buf, console_cmd_arg_get(1)) == 0) {
            texture_get_or_load(resource_pack_entry_name_buf, resource_pack_entry_name_buf);
            freeware_brushes.push_back(new freeware_editor_brush(
                resource_pack_entry_name_buf, freeware_tile_header.width, freeware_tile_header.height));
            fclose(file);
            console_printf(&console_log_queue, "...tile '%s' added to tile library\n", resource_pack_entry_name_buf);
            return;
        }
        fseek(file, entry_size - sizeof(freeware_tile_header), SEEK_CUR);
    }

    console_printf(&console_log_queue, "Tile '%s' not found in '%s'\n", console_cmd_arg_get(1),
                   (char *)grim_interface_ptr->grim_get_config_var(resource_pack_path).words[3]);
    fclose(file);
}
