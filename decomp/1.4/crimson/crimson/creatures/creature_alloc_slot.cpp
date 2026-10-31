#include "crimsonland_gameplay.h"

extern "C" int creature_alloc_slot(void)
{
    for (int index = 0; index < (int)(sizeof(creature_pool) / sizeof(creature_pool[0])); ++index) {
        if (!creature_pool[index].active) {
            creature_pool[index].hit_flash_timer = -1.0f;
            return index;
        }
    }
    return 0;
}
