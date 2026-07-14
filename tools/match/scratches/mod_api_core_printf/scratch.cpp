#include <stdarg.h>

#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

extern "C" char mod_api_core_format_buffer[];
extern "C" void mod_api_debug_printf(char *format, ...);

void mod_api_cpp_t::mod_api_core_printf(char *format, ...)
{
    va_list args;
    va_start(args, format);
    crt_vsprintf(mod_api_core_format_buffer, format, args);
    mod_api_debug_printf(mod_api_core_format_buffer);
    console_log_queue.console_push_line(mod_api_core_format_buffer);
}
