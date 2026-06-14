#include "crimsonland_gameplay.h"

extern "C" bonus_entry_t *bonus_alloc_slot(void)
{
    int index = 0;
    bonus_entry_t *bonus = bonus_pool;
    do {
        if (bonus->bonus_id == BONUS_ID_NONE) {
            return &bonus_pool[index];
        }
        ++bonus;
        ++index;
    } while (bonus < &bonus_pool[0x10]);
    return &bonus_pool_sentinel;
}
