#include "crimsonland_gameplay.h"

extern "C" unsigned char creatures_none_active(void)
{
    for (int i = 0; i < 0x180; i++) {
        if (creature_pool[i].active) {
            creatures_any_active_flag = 0;
            return 0;
        }
    }

    creatures_any_active_flag = 1;
    return 1;
}
