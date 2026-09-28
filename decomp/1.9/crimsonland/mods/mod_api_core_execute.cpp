#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

void mod_api_cpp_t::mod_api_core_execute(char *string)
{
    console_log_queue.exec_line(string);
}
