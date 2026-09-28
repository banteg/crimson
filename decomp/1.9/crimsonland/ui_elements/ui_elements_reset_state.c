#include "crimsonland_gameplay.h"

void ui_elements_reset_state(void)
{
    int i;
    for (i = 0; i < 41; i++) {
        ui_element_table[i]->active = 0;
        ui_element_table[i]->hover_amount = 0;
    }
}
