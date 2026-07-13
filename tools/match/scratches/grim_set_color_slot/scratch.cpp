#include "grim2d_cpp.h"

extern unsigned long grim_color_slot0[4];

void IGrim2D_cpp::grim_set_color_slot(
    int index, float r, float g, float b, float a)
{
    unsigned long color =
        (((unsigned long)(a * 255.0f) & 0xff) << 24) |
        (((unsigned long)(r * 255.0f) & 0xff) << 16) |
        (((unsigned long)(g * 255.0f) & 0xff) << 8) |
        ((unsigned long)(b * 255.0f) & 0xff);

    grim_color_slot0[index] = color;
}
