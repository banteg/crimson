#include "grim2d_cpp.h"

extern unsigned long grim_color_slot0[4];

void IGrim2D_cpp::grim_set_color(float r, float g, float b, float a)
{
    if (a > 1.0f) {
        a = 1.0f;
    } else if (a < 0.0f) {
        a = 0.0f;
    }

    unsigned long color =
        (((unsigned long)(a * 255.0f) & 0xff) << 24) |
        (((unsigned long)(r * 255.0f) & 0xff) << 16) |
        (((unsigned long)(g * 255.0f) & 0xff) << 8) |
        ((unsigned long)(b * 255.0f) & 0xff);

    grim_color_slot0[0] = color;
    grim_color_slot0[1] = grim_color_slot0[2] = grim_color_slot0[3] =
        grim_color_slot0[0];
}
