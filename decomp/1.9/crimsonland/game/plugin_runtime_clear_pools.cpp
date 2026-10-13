#include "crimsonland_gameplay.h"

extern "C" void plugin_runtime_clear_pools(void)
{
    int index;
    for (index = 0; index < 0x10; ++index) {
        bonus_pool[index].bonus_id = BONUS_ID_NONE;
    }
    for (index = 0; index < 0x180; ++index) {
        creature_pool[index].active = 0;
        creature_pool[index].health = -1.0f;
    }
    for (index = 0; index < PROJECTILE_POOL_CAPACITY; ++index) {
        projectile_pool[index].active = 0;
    }

    for (index = 0; index < 2; ++index) {
        player_state_table[index].entity_active = 0;
        player_state_table[index].health = -1.0f;
    }
}
