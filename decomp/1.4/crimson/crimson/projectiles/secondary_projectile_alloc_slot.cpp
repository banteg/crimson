#include "crimsonland_gameplay.h"

extern "C" int secondary_projectile_alloc_slot(void)
{
    const int count = sizeof(secondary_projectile_pool) / sizeof(secondary_projectile_pool[0]);
    for (int index = 0; index < count; ++index) {
        if (!secondary_projectile_pool[index].active)
            return index;
    }
    return count - 1;
}
