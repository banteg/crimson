#include "grim2d_cpp.h"

#if CL_BUILD < 10900
extern float grim_ms_to_seconds_scale;
extern float grim_time_ms;
extern __int64 grim_time_ticks;

void IGrim2D_cpp::grim_set_time_ms(float seconds)
{
    grim_time_ms = seconds;
    grim_time_ticks = (__int64)((1.0f / grim_ms_to_seconds_scale) * seconds);
}
#else
extern int grim_time_ms;

void IGrim2D_cpp::grim_set_time_ms(int ms)
{
    grim_time_ms = ms;
}
#endif
