#include "crimsonland_gameplay.h"

void ui_elements_reset_state(void)
{
    ui_element_t **element = ui_element_table;
    do {
        (*element)->active = 0;
        (*element)->hover_amount = 0;
        ++element;
    } while ((int)element < (int)&ui_element_table[41]);
}
