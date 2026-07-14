#include "crimsonland_gameplay.h"

int ui_elements_max_timeline(void)
{
    int max_timeline = 0;
    ui_element_t **element = ui_element_table;

    do {
        if ((*element)->active && max_timeline < (*element)->timeline_end_ms) {
            max_timeline = (*element)->timeline_end_ms;
        }
        ++element;
    } while ((int)element < (int)&ui_element_table[41]);

    return max_timeline;
}
