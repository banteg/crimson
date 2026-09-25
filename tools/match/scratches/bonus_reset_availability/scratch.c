#include "crimsonland_gameplay.h"

void bonus_reset_availability(void)
{
    int i;
    for (i = 0; i < 15; i++) {
        bonus_meta_table[i].enabled = 1;
    }

    bonus_meta_table[BONUS_ID_NONE].enabled = 0;
}
