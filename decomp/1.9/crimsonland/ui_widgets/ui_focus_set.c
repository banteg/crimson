#include "crimsonland_ui.h"

void ui_focus_set(int id, char reset_timer)
{
    int i;

    if (ui_focus_candidates[ui_focus_index] == id) {
        return;
    }

    if (reset_timer) {
        ui_focus_timer_ms = 1000;
    }

    for (i = 0; i < ui_focus_count; i++) {
        if (ui_focus_candidates[i] == id) {
            ui_focus_index = i;
            return;
        }
    }
}
