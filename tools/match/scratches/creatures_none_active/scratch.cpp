#include "crimsonland_gameplay.h"

extern "C" unsigned char creatures_none_active(void)
{
    creature_t *creature = creature_pool;

    while ((int)creature < (int)&creature_pool[0x180]) {
        if (creature->active) {
            creatures_any_active_flag = 0;
            return 0;
        }
        ++creature;
    }

    creatures_any_active_flag = 1;
    return 1;
}
