#include "crimsonland_gameplay.h"

int creature_spawn_slot_alloc(void)
{
    int index = 0;
    creature_spawn_slot_t *slot;

    for (slot = creature_spawn_slot_table;
         (int)slot < (int)&creature_spawn_slot_table[32];
         ++slot) {
        if (slot->owner == 0) {
            return index;
        }
        ++index;
    }

    return 31;
}
