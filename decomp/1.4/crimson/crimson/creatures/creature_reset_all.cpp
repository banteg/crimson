#include "crimsonland_gameplay.h"

extern "C" void creature_reset_all(void)
{
    int i;
#if CL_BUILD < 10300
    for (i = 0; i < 0x80; i++) {
        creature_pool[i].active = 0;
    }
#else
    for (i = 0; i < 0x200; i++) {
        creature_pool[i].active = 0;
    }
#endif
}
