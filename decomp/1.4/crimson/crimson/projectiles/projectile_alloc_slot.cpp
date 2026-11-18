#include "crimsonland_gameplay.h"

extern "C" int projectile_alloc_slot(void)
{
    const int count = sizeof(projectile_pool) / sizeof(projectile_pool[0]);
    for (int index = 0; index < count; ++index) {
        if (!projectile_pool[index].active)
            return index;
    }
    return count - 1;
}
