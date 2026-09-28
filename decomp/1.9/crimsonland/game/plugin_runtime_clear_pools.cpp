#include "crimsonland_gameplay.h"
#include <stddef.h>

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
    for (index = 0; index < 0x60; ++index) {
        projectile_pool[index].active = 0;
    }

    float *player_health = &player_state_table[0].health;
    do {
        player_state_t *player = (player_state_t *)(
            (char *)player_health - offsetof(player_state_t, health));
        player->entity_active = 0;
        *player_health = -1.0f;
        player_health = (float *)(
            (unsigned char *)player_health + sizeof(player_state_t));
    } while ((int)player_health
             < (int)&player_state_table[2].health);
}
