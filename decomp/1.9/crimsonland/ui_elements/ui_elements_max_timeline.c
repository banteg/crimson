#include "crimsonland_gameplay.h"

int ui_elements_max_timeline(void)
{
    int max_timeline = 0;
    int i;
    for (i = 0; i < 41; i++) {
        if (ui_element_table[i]->active && max_timeline < ui_element_table[i]->timeline_end_ms) {
            max_timeline = ui_element_table[i]->timeline_end_ms;
        }
    }

    return max_timeline;
}
