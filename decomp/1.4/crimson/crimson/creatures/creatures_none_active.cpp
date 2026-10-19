#include "crimsonland_gameplay.h"

extern "C" unsigned char creatures_none_active(void)
{
    for (int i = 0; i < 0x200; i++) {
        if (creature_pool[i].active) {
            return 0;
        }
    }

    return 1;
}
