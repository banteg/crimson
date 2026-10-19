#include "crimsonland_gameplay.h"

extern "C" void projectile_pool_global_init(void)
{
    int remaining = PROJECTILE_POOL_CAPACITY;
    projectile_t *entry = projectile_pool;

    do {
#if CL_BUILD >= 10900
        entry->fields.owner_id = -1;
#endif
        entry->active = 0;
        entry->fields.type_id = PROJECTILE_TYPE_PISTOL;
        entry->fields.speed_scale = 1.0f;
#if CL_BUILD >= 10900
        entry->fields.hit_radius = 0.0f;
        entry->fields.projectile_speed = 1.0f;
#endif
        ++entry;
    } while (--remaining != 0);
}
