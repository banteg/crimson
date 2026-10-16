#include "crimsonland_gameplay.h"

extern "C" int perk_select_random(void)
{
    int perk_id;
    int attempt = 0;

    while (++attempt <= 1000) {
        perk_id = crt_rand() % perk_id_max + 1;
        if (perk_meta_table[perk_id].available == 0) {
            continue;
        }
        if ((char)perk_can_offer(perk_id) == 0) {
            continue;
        }
        return perk_id;
    }

#if CL_BUILD == 10908
    // 1.9.8's message lacks the "to".
    console_printf(&console_log_queue, "Perk Randomizer failed generate a random perk!\n");
#else
    console_printf(&console_log_queue, "Perk Randomizer failed to generate a random perk!\n");
#endif
    return perk_id_instant_winner;
}
