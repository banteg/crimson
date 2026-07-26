#include "grim2d_cpp.h"

union GrimPackedColor {
    unsigned long value;
    unsigned char channel[4];
};

extern unsigned long grim_color_slot0[4];

void IGrim2D_cpp::grim_set_color_ptr(float *rgba)
{
    GrimPackedColor color;

    color.channel[3] = (unsigned char)(rgba[3] * 255.0f);
    color.channel[2] = (unsigned char)(rgba[0] * 255.0f);
    color.channel[1] = (unsigned char)(rgba[1] * 255.0f);
    color.channel[0] = (unsigned char)(rgba[2] * 255.0f);

    grim_color_slot0[0] = color.value;
    grim_color_slot0[1] = grim_color_slot0[2] = grim_color_slot0[3] =
        grim_color_slot0[0];
}
