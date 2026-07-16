#include "crimsonland_gameplay.h"

extern "C" void secondary_projectile_pool_global_init(void)
{
    int remaining = 0x40;
    secondary_projectile_t *entry = secondary_projectile_pool;

    do {
        entry->active = 0;
        entry->pos.vx.vy.type_id = SECONDARY_PROJECTILE_TYPE_ROCKET;
        entry->life_timer = 0.0f;
        entry->pos.vx.vy.trail_timer = 0.0f;
        entry->pos.vx.vy.unused_0x28 = (unsigned int)-100;
        ++entry;
    } while (--remaining != 0);
}
