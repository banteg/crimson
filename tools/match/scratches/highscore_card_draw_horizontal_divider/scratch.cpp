#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" float highscore_card_divider_color_r;

extern "C" void highscore_card_draw_horizontal_divider(float *xy)
{
    grim_interface_ptr->grim_set_color_ptr(&highscore_card_divider_color_r);
    xy[0] -= 16.0f;
    grim_interface_ptr->grim_draw_rect_outline(xy, 192.0f, 1.0f);
    xy[0] += 16.0f;
    xy[1] += 4.0f;
}
