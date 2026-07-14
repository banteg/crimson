#include "crimsonland_gameplay.h"

void perks_rebuild_available(void)
{
    int remaining = perk_id_max + 1;
    if (remaining > 0) {
        int *available = &perk_meta_table[0].available;
        do {
            *(unsigned char *)available = 0;
            available += sizeof(perk_meta_t) / sizeof(int);
            --remaining;
        } while (remaining != 0);
    }

    {
        int antiperk_id = perk_id_antiperk;
        unsigned char *available = (unsigned char *)&perk_meta_table[1].available;
        unsigned char one = 1;
        *(unsigned char *)&perk_meta_table[antiperk_id].available = 0;
        do {
            *available = one;
            available += sizeof(perk_meta_t);
        } while ((int)available < (int)&perk_meta_table[28].available);

        {
            int man_bomb_id = perk_id_man_bomb;
            int living_fortress_id = perk_id_living_fortress;
            int fire_caugh_id = perk_id_fire_caugh;
            *(unsigned char *)&perk_meta_table[man_bomb_id].available = one;
            *(unsigned char *)&perk_meta_table[living_fortress_id].available = one;
            *(unsigned char *)&perk_meta_table[fire_caugh_id].available = one;
            *(unsigned char *)&perk_meta_table[perk_id_tough_reloader].available = one;

            {
                int unlock_count = quest_unlock_index;
                int index = 0;
                int *unlock_perk_id = &quest_selected_meta[0].unlock_perk_id;
                while (index < unlock_count
                       && (int)unlock_perk_id < (int)&quest_selected_meta[50].unlock_perk_id) {
                    int perk_id = *unlock_perk_id;
                    ++index;
                    unlock_perk_id += sizeof(quest_meta_t) / sizeof(int);
                    *(unsigned char *)&perk_meta_table[perk_id].available = one;
                }
            }
        }

        *(unsigned char *)&perk_meta_table[antiperk_id].available = 0;
    }
}
