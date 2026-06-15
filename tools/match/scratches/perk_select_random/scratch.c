#include "crimsonland_gameplay.h"

int perk_select_random(void)
{
    int attempt = 1;
    int perk_id;

    for (;;) {
        perk_id = crt_rand();
        perk_id = perk_id % perk_id_max + 1;
        if ((unsigned char)perk_meta_table[perk_id].available) {
            if ((unsigned char)perk_can_offer(perk_id)) {
                break;
            }
        }
        ++attempt;
        if (attempt <= 1000) {
            continue;
        }

        console_printf(&console_log_queue, "Perk Randomizer failed to generate a random perk!\n");
        return perk_id_instant_winner;
    }

    return perk_id;
}
