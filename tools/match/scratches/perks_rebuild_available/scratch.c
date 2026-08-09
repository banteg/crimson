#include "crimsonland_gameplay.h"

void perks_rebuild_available(void)
{
    int remaining = perk_id_max + 1;
    if (remaining > 0) {
        unsigned char *available = &perk_meta_table[0].available;
        do {
            *available = 0;
            available += sizeof(perk_meta_t);
            --remaining;
        } while (remaining != 0);
    }

    {
        int antiperk_index =
            perk_id_antiperk * (sizeof(perk_meta_t) / sizeof(int));
        unsigned char *available = &perk_meta_table[1].available;
        unsigned char one = 1;
        (&perk_meta_table[0].available)[antiperk_index * sizeof(int)] = 0;
        do {
            *available = one;
            available += sizeof(perk_meta_t);
        } while ((int)available < (int)&perk_meta_table[28].available);

        {
            int man_bomb_id = perk_id_man_bomb;
            int living_fortress_id = perk_id_living_fortress;
            int fire_caugh_id = perk_id_fire_caugh;
            perk_meta_table[man_bomb_id].available = one;
            perk_meta_table[living_fortress_id].available = one;
            perk_meta_table[fire_caugh_id].available = one;
            perk_meta_table[perk_id_tough_reloader].available = one;

            {
                int unlock_count = quest_unlock_index;
                int index = 0;
                if (unlock_count > 0) {
                    for (; index < unlock_count; ++index) {
                        int perk_id;
                        if ((int)&quest_selected_meta[index].unlock_perk_id
                            >= (int)&quest_selected_meta[50].unlock_perk_id) {
                            break;
                        }
                        perk_id = quest_selected_meta[index].unlock_perk_id;
                        perk_meta_table[perk_id].available = one;
                    }
                }
            }
        }

        (&perk_meta_table[0].available)[antiperk_index * sizeof(int)] = 0;
    }
}
