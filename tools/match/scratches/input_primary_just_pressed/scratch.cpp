#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern unsigned char console_open_flag;
extern unsigned char input_primary_latch;

extern "C" bool input_primary_just_pressed(void)
{
    int i;
    bool flag;

    if (!console_open_flag) {
        if (!input_primary_latch) {
            flag = 1;
            if (grim_interface_ptr->grim_is_mouse_button_down(0)) {
                input_primary_latch = flag;
            }
            for (i = 0; i < 2; i++) {
                if (grim_interface_ptr->grim_is_key_active(
                        player_state_table[i].input.fire_key)) {
                    input_primary_latch = 1;
                }
            }
            if (input_primary_latch) {
                return flag;
            }
        } else {
            flag = 1;
            if (grim_interface_ptr->grim_is_mouse_button_down(0)) {
                flag = 0;
            }
            for (i = 0; i < 2; i++) {
                if (grim_interface_ptr->grim_is_key_active(
                        player_state_table[i].input.fire_key)) {
                    flag = 0;
                }
            }
            if (flag) {
                input_primary_latch = 0;
            }
        }
    }
    return 0;
}
