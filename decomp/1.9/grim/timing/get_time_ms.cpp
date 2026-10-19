#include "grim2d_cpp.h"

#if CL_BUILD < 10900
extern float grim_time_ms;

float IGrim2D_cpp::grim_get_time_ms(void)
{
    return grim_time_ms;
}
#else
extern int grim_time_ms;

int IGrim2D_cpp::grim_get_time_ms(void)
{
    return grim_time_ms;
}
#endif
