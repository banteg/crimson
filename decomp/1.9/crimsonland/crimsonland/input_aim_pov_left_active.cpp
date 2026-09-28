#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" bool input_aim_pov_left_active(void)
{
    return grim_interface_ptr->grim_get_joystick_pov(0)
        == config_blob.aim_pov_left;
}
