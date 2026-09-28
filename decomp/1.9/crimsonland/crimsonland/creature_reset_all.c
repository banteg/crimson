#include "crimsonland_gameplay.h"

void creature_reset_all(void)
{
    int i;
    for (i = 0; i < 0x180; i++) {
        creature_pool[i].active = 0;
        if ((creature_pool[i].flags & 4) != 0) {
            creature_spawn_slot_table[creature_pool[i].link_index].owner = 0;
        }
    }
}
