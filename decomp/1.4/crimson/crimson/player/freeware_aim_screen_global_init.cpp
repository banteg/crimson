#include "crimsonland_types.h"

extern "C" vec2f_t freeware_aim_screen;

extern "C" void freeware_aim_screen_global_init()
{
    freeware_aim_screen.x = 320.0f;
    freeware_aim_screen.y = 240.0f;
}
