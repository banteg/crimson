#include "crimsonland_gameplay.h"

extern "C" void creature_spawn_slot_table_global_init(void)
{
    int remaining = 0x20;
    creature_spawn_slot_t *slot = creature_spawn_slot_table;

    do {
        slot->owner = 0;
        slot->interval_s = 0.5f;
        slot->timer_s = 0.5f;
        slot->count = 0;
        slot->limit = -1;
        ++slot;
    } while (--remaining != 0);
}
