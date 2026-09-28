#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

char mod_api_cpp_t::mod_api_inp_get_pressed_char(void)
{
    return (char)grim_interface_ptr->grim_get_key_char();
}
