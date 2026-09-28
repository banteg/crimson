#include "grim2d_cpp.h"

extern "C" int grim_run_loop(void);

bool IGrim2D_cpp::grim_apply_settings(void)
{
    grim_run_loop();
    return true;
}
