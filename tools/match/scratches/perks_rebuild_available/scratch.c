#include "crimsonland_gameplay.h"

void perks_rebuild_available(void)
{
    int i;

    for (i = 0; i < perk_id_max + 1; i++) {
        perk_meta_table[i].available = 0;
    }

    perk_meta_table[perk_id_antiperk].available = 0;
    for (i = 1; i < 28; i++) {
        perk_meta_table[i].available = 1;
    }
    perk_meta_table[perk_id_man_bomb].available = 1;
    perk_meta_table[perk_id_living_fortress].available = 1;
    perk_meta_table[perk_id_fire_caugh].available = 1;
    perk_meta_table[perk_id_tough_reloader].available = 1;

    for (i = 0; i < quest_unlock_index && i < 50; i++) {
        perk_meta_table[quest_selected_meta[i].unlock_perk_id].available = 1;
    }

    perk_meta_table[perk_id_antiperk].available = 0;
}
