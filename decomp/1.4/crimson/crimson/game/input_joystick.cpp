#include "freeware_config.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" bool input_aim_pov_left_active(void)
{
    return grim_interface_ptr->grim_get_joystick_pov(0) == config_blob.pov_left;
}

extern "C" bool input_aim_pov_right_active(void)
{
    return grim_interface_ptr->grim_get_joystick_pov(0) == config_blob.pov_right;
}

extern "C" bool input_move_up_active(void)
{
    return grim_interface_ptr->grim_get_joystick_y() - config_blob.pad_center_y < -config_blob.pad_threshold;
}

extern "C" bool input_move_down_active(void)
{
    return grim_interface_ptr->grim_get_joystick_y() - config_blob.pad_center_y > config_blob.pad_threshold;
}

extern "C" bool input_move_left_active(void)
{
    return grim_interface_ptr->grim_get_joystick_x() - config_blob.pad_center_x < -config_blob.pad_threshold;
}

extern "C" bool input_move_right_active(void)
{
    return grim_interface_ptr->grim_get_joystick_x() - config_blob.pad_center_x > config_blob.pad_threshold;
}
