#include "crimsonland_gameplay.h"

struct plugin_player_t {
    unsigned char active;
    unsigned char _pad0[0x23];
    float health;
    unsigned char _pad1[0x338];
};

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

    float *player_health = &((plugin_player_t *)player_state_table)[0].health;
    do {
        *((unsigned char *)player_health - 0x24) = 0;
        *player_health = -1.0f;
        player_health = (float *)((unsigned char *)player_health + sizeof(plugin_player_t));
    } while ((int)player_health
             < (int)((unsigned char *)((plugin_player_t *)player_state_table + 2) + 0x24));
}
