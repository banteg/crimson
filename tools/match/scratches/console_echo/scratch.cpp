#include <string.h>

#include "crimsonland_console.h"

extern "C" int console_cmd_argc_get(void);

extern "C" void console_echo(void)
{
    if (console_cmd_argc_get() == 2
        && strcmp("off", console_cmd_arg_get(1)) == 0) {
        console_log_queue.echo_enabled = 0;
        return;
    }

    if (console_cmd_argc_get() == 2
        && strcmp("on", console_cmd_arg_get(1)) == 0) {
        console_log_queue.echo_enabled = 1;
        return;
    }

    int index = 1;
    if (console_cmd_argc_get() > 1) {
        do {
            console_printf(
                &console_log_queue, "%s ", console_cmd_arg_get(index));
            ++index;
        } while (index < console_cmd_argc_get());
    }
    console_printf(&console_log_queue, "\n");
}
