#include "crimsonland_gameplay.h"

extern "C" void creature_pool_global_init(void)
{
    int remaining = 0x181;
    creature_t *entry = creature_pool;

    do {
        entry->entity_reserved_74 = 0;
        entry->phase_seed = 0;
        entry->hit_flash_timer = 0.0f;
        entry->active = 0;
        entry->ai_mode = 0;
        entry->state_flag = 0;
        entry->anim_phase = 0.0f;
        entry->collision_flag = 0;
        entry->collision_timer = 0.0f;
        entry->link_index = -1;
        ++entry;
    } while (--remaining != 0);
}
