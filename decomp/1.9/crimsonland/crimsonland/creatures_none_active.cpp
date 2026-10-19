#include "crimsonland_gameplay.h"

extern "C" unsigned char creatures_none_active(void)
{
#if CL_BUILD < 10900
    for (int i = 0; i < 0x200; i++) {
        if (creature_pool[i].active) {
            return 0;
        }
    }

    return 1;
#else
    for (int i = 0; i < 0x180; i++) {
        if (creature_pool[i].active) {
            creatures_none_active_flag = 0;
            return 0;
        }
    }

    creatures_none_active_flag = 1;
    return 1;
#endif
}
