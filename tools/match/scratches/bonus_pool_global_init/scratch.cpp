#include "crimsonland_gameplay.h"

extern "C" void bonus_pool_global_init(void)
{
    int remaining = 0x10;
    bonus_entry_t *entry = bonus_pool;

    do {
        entry->bonus_id = BONUS_ID_NONE;
        ++entry;
    } while (--remaining != 0);
}
