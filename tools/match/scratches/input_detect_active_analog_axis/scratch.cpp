#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" int input_detect_active_analog_axis(void)
{
    float value0 = grim_interface_ptr->grim_get_config_float(0x13f);
    *(unsigned int *)&value0 &= 0x7fffffff;
    if (value0 > 0.5f) {
        return 0x13f;
    }
    float value1 = grim_interface_ptr->grim_get_config_float(0x140);
    *(unsigned int *)&value1 &= 0x7fffffff;
    if (value1 > 0.5f) {
        return 0x140;
    }
    float value2 = grim_interface_ptr->grim_get_config_float(0x141);
    *(unsigned int *)&value2 &= 0x7fffffff;
    if (value2 > 0.5f) {
        return 0x141;
    }
    float value3 = grim_interface_ptr->grim_get_config_float(0x153);
    *(unsigned int *)&value3 &= 0x7fffffff;
    if (value3 > 0.5f) {
        return 0x153;
    }
    float value4 = grim_interface_ptr->grim_get_config_float(0x154);
    *(unsigned int *)&value4 &= 0x7fffffff;
    if (value4 > 0.5f) {
        return 0x154;
    }
    float value5 = grim_interface_ptr->grim_get_config_float(0x155);
    *(unsigned int *)&value5 &= 0x7fffffff;
    if (value5 > 0.5f) {
        return 0x155;
    }

    grim_interface_ptr->grim_flush_input();
    return 0;
}
