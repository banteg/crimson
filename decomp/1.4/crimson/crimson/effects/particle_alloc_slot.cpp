#include "crimsonland_gameplay.h"

extern "C" int particle_alloc_slot(void)
{
    const int count = sizeof(particle_pool) / sizeof(particle_pool[0]);
    for (int index = 0; index < count; ++index) {
        if (!particle_pool[index].active)
            return index;
    }
    return count - 1;
}
