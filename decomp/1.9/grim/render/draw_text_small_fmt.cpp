#include <stdarg.h>

#include "grim2d_cpp.h"

extern "C" __declspec(dllimport) int __cdecl
vsprintf(char *buffer, const char *fmt, va_list args);

extern char grim_printf_buffer_alt[];

void IGrim2D_cpp::grim_draw_text_small_fmt(
    float x, float y, char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsprintf(grim_printf_buffer_alt, fmt, args);
    grim_draw_text_small(x, y, grim_printf_buffer_alt);
}
