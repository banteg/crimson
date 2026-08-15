#include "grim2d_cpp.h"

extern int grim_backbuffer_width;
extern int grim_backbuffer_height;

void IGrim2D_cpp::grim_draw_fullscreen_quad(int)
{
    grim_set_rotation(0.0f);
    grim_begin_batch();
    grim_draw_quad(
        0.0f,
        0.0f,
        (float)(unsigned int)grim_backbuffer_width,
        (float)(unsigned int)grim_backbuffer_height);
    grim_end_batch();
}
