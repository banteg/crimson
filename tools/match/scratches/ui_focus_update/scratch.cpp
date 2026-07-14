#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" unsigned char ui_focus_input_locked;
extern "C" int ui_focus_candidates[32];
extern "C" int ui_focus_count;
extern "C" int ui_focus_index;
extern "C" int ui_focus_frame_marker_ms;
extern "C" int ui_focus_timer_ms;
extern "C" int frame_dt_ms;
extern "C" int game_time_ms;

extern "C" unsigned char ui_focus_update(int id)
{
    unsigned char focused = 0;
    if (id == ui_focus_candidates[ui_focus_index]) {
        focused = 1;
    }

    int slot;
    if (ui_focus_frame_marker_ms != game_time_ms) {
        ui_focus_timer_ms -= frame_dt_ms;
        if (ui_focus_timer_ms < 0) {
            ui_focus_timer_ms = 0;
        }

        if (!ui_focus_input_locked && grim_interface_ptr->grim_was_key_pressed(15)) {
            if (grim_interface_ptr->grim_is_key_down(42)
                || grim_interface_ptr->grim_is_key_down(54)) {
                --ui_focus_index;
            } else {
                ++ui_focus_index;
            }
            ui_focus_timer_ms = 1000;
        }

        if (ui_focus_index < 0) {
            ui_focus_index = ui_focus_count - 1;
        }
        if (ui_focus_index > ui_focus_count - 1) {
            ui_focus_index = 0;
        }

        ui_focus_frame_marker_ms = game_time_ms;
        slot = 0;
    } else {
        slot = ui_focus_count;
        if (slot >= 32) {
            slot = 31;
        }
    }

    ui_focus_candidates[slot] = id;
    ui_focus_count = slot + 1;
    return focused;
}
