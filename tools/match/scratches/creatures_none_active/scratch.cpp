#include "crimsonland_gameplay.h"

extern "C" unsigned char creatures_none_active(void)
{
    creature_t *creature = creature_pool;
loop:
    if (creature->active) {
        creatures_any_active_flag = 0;
        return 0;
    }
    ++creature;
    if ((int)creature < (int)&creature_pool[0x180]) {
        goto loop;
    }

    creatures_any_active_flag = 1;
    return 1;
}
