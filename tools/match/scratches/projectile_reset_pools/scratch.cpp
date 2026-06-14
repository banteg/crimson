#include "crimsonland_gameplay.h"

extern "C" void projectile_reset_pools(void)
{
    projectile_t *projectile = projectile_pool;
    do {
        projectile->active = 0;
        ++projectile;
    } while ((int)projectile < (int)&projectile_pool[0x60]);

    particle_t *particle = particle_pool;
    do {
        particle->active = 0;
        ++particle;
    } while ((int)particle < (int)&particle_pool[0x70]);
}
