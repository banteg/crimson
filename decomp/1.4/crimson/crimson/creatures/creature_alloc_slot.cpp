#include "crimsonland_gameplay.h"

extern "C" int creature_alloc_slot(void)
{
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10002
    const int count = 128;
#else
    const int count = sizeof(creature_pool) / sizeof(creature_pool[0]);
#endif
    for (int index = 0; index < count; ++index) {
        if (!creature_pool[index].active) {
#if CL_BUILD != 10002 && (!defined(FREEWARE_EDITION) || FREEWARE_EDITION != 10002)
            creature_pool[index].hit_flash_timer = -1.0f;
#endif
            return index;
        }
    }
    return 0;
}
