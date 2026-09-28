#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" int input_detect_active_analog_axis(void)
{
    float value0 = grim_interface_ptr->grim_get_config_float(0x13f);
    if (abs_bits(value0) > 0.5f) {
        return 0x13f;
    }
    float value1 = grim_interface_ptr->grim_get_config_float(0x140);
    if (abs_bits(value1) > 0.5f) {
        return 0x140;
    }
    float value2 = grim_interface_ptr->grim_get_config_float(0x141);
    if (abs_bits(value2) > 0.5f) {
        return 0x141;
    }
    float value3 = grim_interface_ptr->grim_get_config_float(0x153);
    if (abs_bits(value3) > 0.5f) {
        return 0x153;
    }
    float value4 = grim_interface_ptr->grim_get_config_float(0x154);
    if (abs_bits(value4) > 0.5f) {
        return 0x154;
    }
    float value5 = grim_interface_ptr->grim_get_config_float(0x155);
    if (abs_bits(value5) > 0.5f) {
        return 0x155;
    }

    grim_interface_ptr->grim_flush_input();
    return 0;
}
