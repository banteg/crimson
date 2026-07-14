#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" float ui_mouse_x;
extern "C" float ui_mouse_y;

float mod_api_cpp_t::mod_api_inp_get_analog(int key)
{
    if (key == 0x163) {
        return ui_mouse_x;
    }
    if (key == 0x164) {
        return ui_mouse_y;
    }
    return grim_interface_ptr->grim_get_config_float(key);
}
