#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

unsigned char mod_api_cpp_t::mod_api_inp_key_down(int key)
{
    if (key == 1) {
        return 0;
    }
    return grim_interface_ptr->grim_is_key_active(key);
}
