#include "crimsonland_gameplay.h"

extern "C" void projectile_reset_pools(void)
{
    int i;
    for (i = 0; i < 0x60; i++) {
        projectile_pool[i].active = 0;
    }
    for (i = 0; i < 0x80; i++) {
        particle_pool[i].active = 0;
    }
}
