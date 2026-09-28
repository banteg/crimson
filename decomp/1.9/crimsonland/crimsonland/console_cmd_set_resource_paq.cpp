#include <stdio.h>

#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" int console_cmd_argc_get(void);
extern "C" FILE *crt_fopen(char *path, char *mode);
extern "C" int crt_fclose(FILE *fp);

extern "C" void console_cmd_set_resource_paq(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(
            &console_log_queue,
            "setresourcepaq <resourcepaq>\n");
        return;
    }

    FILE *fp = crt_fopen(console_cmd_arg_get(1), "rb");
    if (fp == 0) {
        console_printf(
            &console_log_queue,
            "File '%s' not found.\n",
            console_cmd_arg_get(1));
        return;
    }

    crt_fclose(fp);
    grim_interface_ptr->grim_set_config_var(16, console_cmd_arg_get(1));
    console_printf(
        &console_log_queue,
        "Set resource paq to '%s'\n",
        console_cmd_arg_get(1));
}
