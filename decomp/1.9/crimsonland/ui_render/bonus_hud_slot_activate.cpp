#include "crimsonland_gameplay.h"

extern "C" bonus_hud_slot_t bonus_hud_slot_table[];

extern "C" void bonus_hud_slot_activate(
    char *label,
    int icon_id,
    float *timer_ptr,
    float *alt_timer_ptr)
{
    int slot_index;
    for (slot_index = 0; slot_index < 16; slot_index++) {
        if (bonus_hud_slot_table[slot_index].active == 0) {
            goto slot_found;
        }
    }
    return;

slot_found:
    bonus_hud_slot_t *slot = &bonus_hud_slot_table[slot_index];
    slot->slide.timer_ptr = timer_ptr;
    slot->slide.alt_timer_ptr = alt_timer_ptr;
    slot->slide.icon_id = icon_id;
    slot->active = 1;
    slot->slide.slide_x = -184.0f;
    slot->slide.label = label;
    if (config_blob.player_count <= 1) {
        slot->slide.alt_timer_ptr = 0;
    }

    for (slot_index = 0; slot_index < 16; slot_index++) {
        if (bonus_hud_slot_table[slot_index].active != 0) {
            for (int check_index = 16; check_index >= 0; check_index--) {
                if (bonus_hud_slot_table[slot_index].slide.timer_ptr
                    == bonus_hud_slot_table[check_index].slide.timer_ptr) {
                    if (slot_index != check_index) {
                        bonus_hud_slot_table[check_index].active = 0;
                    }
                }
            }
        }
    }
}
