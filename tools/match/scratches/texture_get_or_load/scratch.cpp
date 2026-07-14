#include "crimsonland_audio.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" int texture_get_or_load(char *name, char *path)
{
    int handle = grim_interface_ptr->grim_get_texture_handle(name);
    if (handle == -1) {
        if (grim_interface_ptr->grim_load_texture(name, path)) {
            if (cv_silentloads->value == 0.0f) {
                console_printf(
                    &console_log_queue,
                    "...loading texture '%s' ok\n",
                    path);
            }
            return grim_interface_ptr->grim_get_texture_handle(name);
        }

        console_printf(
            &console_log_queue,
            "...loading texture '%s' failed\n",
            path);
        return -1;
    }
    return handle;
}
