#include "crimsonland_gameplay.h"

int ui_get_element_index(ui_element_t *element)
{
    int index;
    for (index = 0; index < 41; index++) {
        if (element == ui_element_table[index]) {
            return index;
        }
    }

    return -1;
}
