#include "crimsonland_console.h"

extern "C" char *console_cmd_arg_get(int index)
{
    if (console_cmd_argc > 0 && index > 0 && index < console_cmd_argc) {
        return console_cmd_name[index];
    }

    return console_empty_arg;
}
