#include "crimsonland_gameplay.h"

extern "C" void creature_pool_global_init(void)
{
#if CL_BUILD < 10300
    int remaining = 0x80;
    creature_t *entry = creature_pool;

    do {
        entry->active = 0;
        entry->entity_reserved_74 = 0;
        entry->ai_mode = 0;
        entry->hit_flash_timer = 0.0f;
        ++entry;
    } while (--remaining != 0);
#else
    int remaining = 0x200;
    creature_t *entry = creature_pool;

    do {
        entry->active = 0;
        entry->ai_mode = 0;
        entry->entity_reserved_74 = 0;
        entry->state_flag = 0;
        entry->anim_phase = 0.0f;
        entry->hit_flash_timer = -1.0f;
        ++entry;
    } while (--remaining != 0);
#endif
}
