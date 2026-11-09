#include "crimsonland_types.h"

extern "C" creature_t unused_sfx_prefix_creature;

extern "C" void unused_sfx_prefix_creature_global_init(void)
{
    unused_sfx_prefix_creature.freeware.animation = 0.0f;
    unused_sfx_prefix_creature.active = 0;
    unused_sfx_prefix_creature.plague_infected = 0;
    unused_sfx_prefix_creature.hit_flash_timer = 0.0f;
}
