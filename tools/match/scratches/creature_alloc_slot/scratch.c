#include "crimsonland_gameplay.h"

int creature_alloc_slot(void)
{
    int index = 0;
    creature_t *creature = creature_pool;

    while ((int)creature < (int)&creature_pool[0x180]) {
        if (!creature->active) {
            int spawned_count;
            creature_pool[index].flags = 0;
            creature_pool[index].phase_seed = crt_rand() & 0x17f;
            spawned_count = creature_spawned_count + 1;
            creature_pool[index].entity_reserved_74 = 0;
            creature_pool[index].anim_phase = 0.0f;
            creature_spawned_count = spawned_count;
            return index;
        }
        ++creature;
        ++index;
    }

    if (cv_verbose->value != 0.0f) {
        console_printf(&console_log_queue, "No free creatures to spawn!\n");
    }
    return 0x180;
}
