#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern "C" IGrim2D_cpp *freeware_console_grim;

extern "C" bool texture_get_or_load(char *name, char *path)
{
    if (freeware_console_grim->grim_get_texture_handle(name) == -1) {
        if (freeware_console_grim->grim_load_texture(name, path)) {
            console_printf(&console_log_queue, "...loading texture '%s' ok\n", path);
            return false;
        }
        console_printf(&console_log_queue, "...loading texture '%s' failed\n", path);
    }
    return false;
}
