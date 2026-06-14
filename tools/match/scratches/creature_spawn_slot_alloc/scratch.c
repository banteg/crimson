#include "crimsonland_gameplay.h"

int creature_spawn_slot_alloc(void)
{
    int index = 0;
    creature_spawn_slot_t *slot = creature_spawn_slot_table;
loop:
    if (slot->owner == 0) {
        return index;
    }
    slot = slot + 1;
    index = index + 1;
    if ((int)slot < (int)&creature_spawn_slot_table[0x20]) {
        goto loop;
    }
    return 0x1f;
}
