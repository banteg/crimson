#include <string.h>
#include "crimsonland_types.h"
#include "freeware_edition.h"

extern "C" {
extern unsigned char perk_choice_flags[CL_BUILD < 10400 ? 32 : 48];
extern int perk_id_count;
int crt_rand();
}

#if FREEWARE_EDITION == 10002
// 0x402900. Includes owned perks and slot zero.
extern "C" void perks_generate_choices() {
    memset(perk_choice_flags, 0, sizeof(perk_choice_flags));
    int selected = 0;
    for (;;) {
        int available = perk_id_count + 1;
        int id = crt_rand() % available;
        if (!perk_choice_flags[id]) {
            ++selected;
            perk_choice_flags[id] = 1;
            if (selected >= 5)
                break;
        }
    }
}
#elif CL_BUILD == 10300 || CL_BUILD == 10400
extern "C" {
extern unsigned char freeware_show_secret_hints;
extern int perk_id_perk_expert, config_player_count, current_player_index;
extern freeware_perk_entry_t perk_meta_table[CL_BUILD == 10300 ? 32 : 48];
#if CL_BUILD == 10300
extern freeware_player_t player_state_table[2];
#define PERKS(i) player_state_table[i].perks
#else
extern player_state_t player_state_table[2];
#define PERKS(i) player_state_table[i].freeware.perks
#endif
}
#if FREEWARE_EDITION == 10300
#define CHOOSER current_player_index
#else
#define CHOOSER 0
#endif

extern "C" void perks_generate_choices() {
    memset(perk_choice_flags, 0, sizeof(perk_choice_flags));
#if FREEWARE_EDITION == 10300
    for (int selected = 0; selected < 5 + 2 * PERKS(current_player_index)[perk_id_perk_expert]; ++selected) {
#else
    int extra = 0;
    if (PERKS(0)[perk_id_perk_expert] > 0)
        extra = 2;
    for (int remaining = 5 + extra; remaining > 0; --remaining) {
#endif
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
#if FREEWARE_EDITION == 10300
                id = crt_rand() % perk_id_count + 1;
#else
                int tries = 0;
                do {
                    ++tries;
                    id = crt_rand() % perk_id_count + 1;
                } while (perk_meta_table[id].secret == 1 && !freeware_show_secret_hints && tries < 50000);
#endif
            }
        } while (perk_choice_flags[id] || (PERKS(CHOOSER)[id] > 0 && attempts < 50000));
        perk_choice_flags[id] = 1;
    }
}
#endif
