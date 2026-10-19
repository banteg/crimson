#include "crimsonland_console.h"

extern "C" void __stdcall console_tokenize_line(char *line);
extern "C" void crt_free(void *ptr);
extern "C" double crt_atof_l(char *text);

void console_queue_t::exec_line(char *line)
{
    console_tokenize_line(line);
    if (console_cmd_argc != 0) {
        console_cvar_entry_t *cvar = console_cvar_find(console_cmd_name[0]);
        console_command_entry_t *command =
            console_command_find(console_cmd_name[0]);

        if (cvar != 0) {
            if (console_cmd_argc == 2) {
                if (cvar->string_value != 0) {
                    crt_free(cvar->string_value);
                }
                cvar->string_value = 0;
                cvar->string_value = strdup_malloc(console_cmd_name[1]);
                cvar->value = (float)crt_atof_l(console_cmd_name[1]);
                if (echo_enabled) {
                    console_printf(
                        this,
                        "\"%s\" set to \"%s\" (%ff)\n",
                        cvar->name,
                        cvar->string_value,
                        cvar->value);
                }
            } else if (echo_enabled) {
                console_printf(
                    this,
                    "\"%s\" is \"%s\" (%ff)\n",
                    cvar->name,
                    cvar->string_value,
                    cvar->value);
            }
        } else if (command != 0) {
            command->handler();
        } else {
            console_printf(
                this,
                "Unknown command \"%s\"\n",
                console_cmd_name[0]);
        }
    }
}
