#include "crimsonland_gameplay.h"

void bonus_reset_availability(void)
{
    unsigned char *enabled = &bonus_meta_table[0].enabled;
    do {
        *enabled = 1;
        enabled += sizeof(bonus_meta_t);
    } while ((int)enabled < (int)&bonus_meta_table[15].enabled);

    bonus_meta_table[BONUS_ID_NONE].enabled = 0;
}
