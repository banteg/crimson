#include <stdarg.h>
#include <stdio.h>

#include "grim2d_cpp.h"

extern char grim_printf_buffer[];

void IGrim2D_cpp::grim_draw_text_mono_fmt(
    float x, float y, char *fmt, ...)
{
    va_list args;
#if CL_BUILD < 10900
    char buffer[512];
    va_start(args, fmt);
    vsprintf(buffer, fmt, args);
    grim_draw_text_mono(x, y, buffer);
#else
    va_start(args, fmt);
    vsprintf(grim_printf_buffer, fmt, args);
    grim_draw_text_mono(x, y, grim_printf_buffer);
#endif
}
