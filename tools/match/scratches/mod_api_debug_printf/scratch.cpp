#include <stdarg.h>
#include <windows.h>

#include "crimsonland_console.h"

extern "C" void mod_api_debug_printf(char *format, ...)
{
    char output[4092];
    va_list args;
    va_start(args, format);
    crt_vsprintf(output, format, args);
    OutputDebugStringA(output);
}
