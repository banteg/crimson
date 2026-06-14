#include "crimsonland_gameplay.h"

void creature_reset_all(void)
{
    int *flags = &creature_pool[0].flags;
    do {
        ((creature_t *)(flags - 0x23))->active = 0;
        if ((*flags & 4) != 0) {
            creature_spawn_slot_table[flags[-5]].owner = 0;
        }
        flags += 0x26;
    } while ((int)flags < (int)&creature_pool[0x180].flags);
}
