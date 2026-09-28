#include "crimsonland_gameplay.h"

extern "C" void secondary_projectile_pool_global_init(void)
{
    int remaining = 0x40;
    secondary_projectile_t *entry = secondary_projectile_pool;

    do {
        entry->active = 0;
        entry->fields.type_id = SECONDARY_PROJECTILE_TYPE_ROCKET;
        entry->life_timer = 0.0f;
        entry->fields.trail_timer = 0.0f;
        entry->fields.unused_0x28 = (unsigned int)-100;
        ++entry;
    } while (--remaining != 0);
}
