#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

unsigned char mod_api_cpp_t::mod_api_core_del_var(char *id)
{
    return console_log_queue.console_cvar_unregister(id);
}
