#include "crimsonland_gameplay.h"

extern "C" int sprite_effect_alloc_slot(void)
{
    const int count = 256;
    for (int index = 0; index < count; ++index) {
        if (!sprite_effect_pool[index].active)
            return index;
    }
    return count - 1;
}
