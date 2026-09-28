#include "crimsonland_gameplay.h"

void weapon_refresh_available(void)
{
    int i;

    for (i = 0; i < 0x40; i++) {
        weapon_table[i].unlocked = 0;
    }

    weapon_table[WEAPON_ID_PISTOL].unlocked = 1;
    for (i = 0; i < quest_unlock_index && i < 0x32; i++) {
        weapon_table[quest_selected_meta[i].unlock_weapon_id].unlocked = 1;
    }

    if (config_game_mode == GAME_MODE_SURVIVAL) {
        weapon_table[WEAPON_ID_ASSAULT_RIFLE].unlocked = 1;
        weapon_table[WEAPON_ID_SHOTGUN].unlocked = 1;
        weapon_table[WEAPON_ID_SUBMACHINE_GUN].unlocked = 1;
    }

    if (!game_is_full_version()) {
        quest_unlock_index_full = 0;
        weapon_table[WEAPON_ID_NONE].unlocked = 0;
        return;
    }
    if (quest_unlock_index_full >= 40) {
        weapon_table[WEAPON_ID_SPLITTER_GUN].unlocked = 1;
    }
    weapon_table[WEAPON_ID_NONE].unlocked = 0;
}
