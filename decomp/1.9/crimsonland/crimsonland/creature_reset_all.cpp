#include "crimsonland_gameplay.h"

extern "C" void creature_reset_all(void)
{
    int i;
#if CL_BUILD < 10300
    for (i = 0; i < 0x80; i++) {
        creature_pool[i].active = 0;
    }
#elif CL_BUILD < 10900
    for (i = 0; i < 0x200; i++) {
        creature_pool[i].active = 0;
    }
#else
    for (i = 0; i < 0x180; i++) {
        creature_pool[i].active = 0;
        if ((creature_pool[i].flags & 4) != 0) {
            creature_spawn_slot_table[creature_pool[i].link_index].owner = 0;
        }
    }
#endif
}
