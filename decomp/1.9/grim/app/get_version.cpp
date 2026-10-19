#include "grim2d_cpp.h"

float IGrim2D_cpp::grim_get_version(void)
{
#if CL_BUILD == 10300
    return 1.2f;
#else
    return 1.21f;
#endif
}
