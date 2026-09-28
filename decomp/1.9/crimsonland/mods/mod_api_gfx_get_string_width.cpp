#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

int mod_api_cpp_t::mod_api_gfx_get_string_width(char *string)
{
    return grim_interface_ptr->grim_measure_text_width(string);
}
