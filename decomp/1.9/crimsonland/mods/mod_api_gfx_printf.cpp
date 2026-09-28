#include <stdarg.h>

#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" char mod_api_gfx_format_buffer[];

void mod_api_cpp_t::mod_api_gfx_printf(
    float x, float y, char *format, ...)
{
    va_list args;
    va_start(args, format);
    crt_vsprintf(mod_api_gfx_format_buffer, format, args);
    grim_interface_ptr->grim_draw_text_small(x, y, mod_api_gfx_format_buffer);
}
