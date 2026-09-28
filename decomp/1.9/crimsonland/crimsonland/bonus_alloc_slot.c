#include "crimsonland_gameplay.h"

bonus_entry_t *bonus_alloc_slot(void)
{
    int index;
    for (index = 0; index < 0x10; index++) {
        if (bonus_pool[index].bonus_id == BONUS_ID_NONE) {
            return &bonus_pool[index];
        }
    }
    return &bonus_pool_sentinel;
}
