#include "crimsonland_gameplay.h"

void creature_reset_all(void)
{
    unsigned char *active = &creature_pool[0].active;
    int *flags = &creature_pool[0].flags;
    do {
        *active = 0;
        if ((*flags & 4) != 0) {
            creature_spawn_slot_table[flags[-5]].owner = 0;
        }
        active += sizeof(creature_t);
        flags += sizeof(creature_t) / sizeof(*flags);
    } while ((int)flags < (int)&creature_pool[0x180].flags);
}
