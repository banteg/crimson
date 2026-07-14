#include "grim2d_cpp.h"

extern unsigned char grim_paused_flag;

void IGrim2D_cpp::grim_set_paused(int paused)
{
    grim_paused_flag = (unsigned char)paused;
}
