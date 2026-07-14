#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

void mod_api_cpp_t::mod_api_core_add_command(
    char *id, void (*command)(void))
{
    console_log_queue.console_register_command(id, command);
}
