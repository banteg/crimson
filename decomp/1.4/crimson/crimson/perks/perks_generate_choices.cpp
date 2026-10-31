#include <string.h>
#include "crimsonland_types.h"

#if CL_BUILD == 10400
extern "C" {
extern unsigned char perk_choice_flags[48], freeware_show_secret_hints;
extern int perk_id_perk_expert, config_player_count, perk_id_count;
extern player_state_t player_state_table[2];
extern freeware_perk_entry_t perk_meta_table[48];
int crt_rand(void);
}

extern "C" void perks_generate_choices(void)
{
    memset(perk_choice_flags, 0, sizeof(perk_choice_flags));
    int extra = 0;
    if (player_state_table[0].freeware.perks[perk_id_perk_expert] > 0)
        extra = 2;
    for (int remaining = 5 + extra; remaining > 0; --remaining) {
        int id, attempts = 0;
        do {
            ++attempts;
            if (config_player_count == 2) {
                int tries = 0;
                do {
                    ++tries;
                    id = crt_rand() % perk_id_count + 1;
                } while (!perk_meta_table[id].available && tries < 50000);
            } else {
                int tries = 0;
                do {
                    ++tries;
                    id = crt_rand() % perk_id_count + 1;
                } while (perk_meta_table[id].secret == 1 && !freeware_show_secret_hints && tries < 50000);
            }
        } while (perk_choice_flags[id] || (player_state_table[0].freeware.perks[id] > 0 && attempts < 50000));
        perk_choice_flags[id] = 1;
    }
}
#endif
