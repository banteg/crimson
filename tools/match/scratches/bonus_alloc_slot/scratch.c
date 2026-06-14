#include "crimsonland_gameplay.h"

bonus_entry_t *bonus_alloc_slot(void)
{
    int index = 0;
    bonus_entry_t *bonus = bonus_pool;
    for (; (int)bonus < (int)&bonus_pool[0x10]; ++bonus, ++index) {
        if (bonus->bonus_id == BONUS_ID_NONE) {
            return &bonus_pool[index];
        }
    }
    return &bonus_pool_sentinel;
}
