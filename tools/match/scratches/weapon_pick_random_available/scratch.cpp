#include "crimsonland_gameplay.h"

extern "C" int weapon_pick_random_available(void)
{
    int weapon_id;
    do {
        weapon_id = crt_rand();
        weapon_id = weapon_id % 0x21;
        if (weapon_usage_counts[++weapon_id] != 0) {
            unsigned int retry = crt_rand();
            if ((retry & 1) == 0) {
                weapon_id = crt_rand();
                weapon_id = weapon_id % 0x21 + 1;
            }
        }
    } while (
        weapon_table[weapon_id].unlocked == 0
        || (
            config_game_mode == GAME_MODE_QUEST
            && quest_stage_major == 5
            && quest_stage_minor == 10
            && weapon_id == 0x17
        )
    );
    return weapon_id;
}
