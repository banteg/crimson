#include "crimsonland_console.h"

extern "C" void console_cmd_set(void)
{
    if (console_cmd_argc != 3) {
        console_printf(&console_log_queue, "set <var> <value>\n");
        return;
    }

    console_cvar_entry_t *entry = console_log_queue.console_register_cvar(
        console_cmd_name[1], console_cmd_name[2]);
    console_printf(
        &console_log_queue,
        "'%s' set to '%s'\n",
        entry->name,
        entry->string_value);
}
