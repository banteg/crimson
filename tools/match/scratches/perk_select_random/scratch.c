#include "crimsonland_gameplay.h"

int perk_select_random(void)
{
    int perk_id;
    int can_offer;
    int attempt = 1;

    do {
        perk_id = crt_rand();
        perk_id = perk_id % perk_id_max + 1;
        if (perk_meta_table[perk_id].available != 0) {
            can_offer = perk_can_offer(perk_id);
            if ((char)can_offer != 0) {
                return perk_id;
            }
        }
        attempt = attempt + 1;
    } while (attempt <= 1000);

    console_printf(&console_log_queue, "Perk Randomizer failed to generate a random perk!\n");
    return perk_id_instant_winner;
}
