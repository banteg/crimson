#include "crimsonland_gameplay.h"

extern "C" void projectile_pool_global_init(void)
{
    int remaining = 0x60;
    projectile_t *entry = projectile_pool;

    do {
        entry->fields.owner_id = -1;
        entry->active = 0;
        entry->fields.type_id = PROJECTILE_TYPE_PISTOL;
        entry->fields.speed_scale = 1.0f;
        entry->fields.hit_radius = 0.0f;
        entry->fields.travel_budget = 1.0f;
        ++entry;
    } while (--remaining != 0);
}
