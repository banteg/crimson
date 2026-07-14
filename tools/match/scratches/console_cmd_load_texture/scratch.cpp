#include "crimsonland_console.h"

extern "C" int console_cmd_argc_get(void);
extern "C" int texture_get_or_load(char *name, char *path);

extern "C" void console_cmd_load_texture(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(
            &console_log_queue,
            "loadtexture <texturefileid>\n");
        return;
    }

    texture_get_or_load(
        console_cmd_arg_get(2),
        console_cmd_arg_get(2));
}
