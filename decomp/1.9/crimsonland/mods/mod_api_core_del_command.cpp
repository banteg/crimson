#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

unsigned char mod_api_cpp_t::mod_api_core_del_command(char *id)
{
    return console_log_queue.console_command_unregister(id);
}
