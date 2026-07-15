#include "crimsonland_gameplay.h"

extern "C" void projectile_pool_global_init(void)
{
    int remaining = 0x60;
    projectile_t *entry = projectile_pool;

    do {
        entry->pos.tail.vy.owner_id = -1;
        entry->active = 0;
        entry->pos.tail.vy.type_id = PROJECTILE_TYPE_PISTOL;
        entry->pos.tail.vy.speed_scale = 1.0f;
        entry->pos.tail.vy.hit_radius = 0.0f;
        entry->pos.tail.vy.travel_budget = 1.0f;
        ++entry;
    } while (--remaining != 0);
}
