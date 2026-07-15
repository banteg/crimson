#include "crimsonland_gameplay.h"

extern "C" bonus_hud_slot_t bonus_hud_slot_table[];

extern "C" void bonus_hud_slot_activate(
    char *label,
    int icon_id,
    float *timer_ptr,
    float *alt_timer_ptr)
{
    int slot_index = 0;
    bonus_hud_slot_t *slot_cursor = &bonus_hud_slot_table[0];
    while ((int)slot_cursor < (int)&bonus_hud_slot_table[16]) {
        if (slot_cursor->active == 0) {
            goto slot_found;
        }
        ++slot_cursor;
        ++slot_index;
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

    slot_index = 0;
    bonus_hud_slot_t *current_slot = &bonus_hud_slot_table[0];
    do {
        if (current_slot->active != 0) {
            int check_index = 16;
            bonus_hud_slot_t *scan = &bonus_hud_slot_table[16];
            do {
                float *current_timer = current_slot->slide.timer_ptr;
                float *scanned_timer = scan->slide.timer_ptr;
                if (current_timer == scanned_timer) {
                    if (slot_index != check_index) {
                        scan->active = 0;
                    }
                }
                --scan;
                --check_index;
            } while ((int)scan >= (int)&bonus_hud_slot_table[0]);
        }
        ++current_slot;
        ++slot_index;
    } while ((int)&current_slot->slide.timer_ptr <
             (int)&bonus_hud_slot_table[16].slide.timer_ptr);
}
