#include "crimsonland_gameplay.h"

extern "C" void credits_line_clear_flag(int index)
{
    while (index >= 0) {
        if ((credits_line_table[index].flags & 4) != 0) {
            credits_line_table[index].flags &= ~4;
            sfx_play(sfx_trooper_inpain_01, 1.0f);
            return;
        }
        --index;
    }
}
