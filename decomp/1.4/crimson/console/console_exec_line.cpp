#include "crimsonland_console.h"

extern "C" void __stdcall console_tokenize_line(char *line);
extern "C" void crt_free(void *ptr);
extern "C" double crt_atof_l(char *text);

void console_queue_t::exec_line(char *line)
{
    console_tokenize_line(line);
    if (console_cmd_argc == 0) {
        return;
    }
    console_cvar_entry_t *cvar = console_cvar_find(console_cmd_name[0]);
    console_command_entry_t *command =
        console_command_find(console_cmd_name[0]);
    if (cvar != 0) {
        console_printf(
            this,
            "\"%s\" is \"%s\"",
            cvar->name,
            cvar->string_value);
        return;
    }
    if (command != 0) {
        command->handler();
        return;
    }
    console_printf(
        this,
        "Unknown command \"%s\"",
        console_cmd_name[0]);
}
