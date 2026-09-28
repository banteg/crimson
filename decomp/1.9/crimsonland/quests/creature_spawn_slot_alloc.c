#include "crimsonland_gameplay.h"

int creature_spawn_slot_alloc(void)
{
    int index;
    for (index = 0; index < 32; index++) {
        if (creature_spawn_slot_table[index].owner == 0) {
            return index;
        }
    }

    return 31;
}
