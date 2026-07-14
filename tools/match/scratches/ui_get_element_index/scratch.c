#include "crimsonland_ui.h"

int ui_get_element_index(ui_element_t *element)
{
    int index = 0;
    ui_element_t **cursor = &ui_element_table_end;

    while ((int)cursor < (int)&ui_perk_prompt_element) {
        if (element == *cursor) {
            return index;
        }

        cursor++;
        index++;
    }

    return -1;
}
