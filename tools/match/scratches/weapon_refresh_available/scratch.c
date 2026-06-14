#include "crimsonland_gameplay.h"

void weapon_refresh_available(void)
{
    unsigned char *unlocked = &weapon_table[0].unlocked;
    int unlock_count;
    int index;
    int one;
    do {
        *unlocked = 0;
        unlocked += sizeof(weapon_stats_t);
    } while ((int)unlocked < (int)&weapon_table[0x40].unlocked);

    unlock_count = quest_unlock_index;
    one = 1;
    index = 0;
    weapon_table[1].unlocked = (unsigned char)one;
    if (quest_unlock_index > 0) {
        int *unlock_weapon_id = &quest_selected_meta[0].unlock_weapon_id;
        while (index < unlock_count) {
            int weapon_id;
            if ((int)unlock_weapon_id >= (int)&quest_selected_meta[0x32].unlock_weapon_id) {
                break;
            }
            weapon_id = *unlock_weapon_id;
            unlock_weapon_id += sizeof(quest_meta_t) / sizeof(int);
            ++index;
            weapon_table[weapon_id].unlocked = (unsigned char)one;
        }
    }

    if (config_game_mode == GAME_MODE_SURVIVAL) {
        weapon_table[2].unlocked = (unsigned char)one;
        weapon_table[3].unlocked = (unsigned char)one;
        weapon_table[5].unlocked = (unsigned char)one;
    }

    if (!(unsigned char)game_is_full_version()) {
        quest_unlock_index_full = 0;
        weapon_table[0].unlocked = 0;
        return;
    }
    if (quest_unlock_index_full >= 40) {
        weapon_table[29].unlocked = (unsigned char)one;
    }
    weapon_table[0].unlocked = 0;
}
