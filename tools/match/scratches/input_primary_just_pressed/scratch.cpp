#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;
extern unsigned char console_open_flag;
extern unsigned char input_primary_latch;

extern "C" bool input_primary_just_pressed(void)
{
    int *fire_key;
    int key_state;
    bool flag;
    int *held_key;

    if (!console_open_flag) {
        if (!input_primary_latch) {
            flag = 1;
            if (grim_interface_ptr->grim_is_mouse_button_down(0)) {
                input_primary_latch = flag;
            }
            fire_key = &player_state_table[0].input.fire_key;
            do {
                key_state = (unsigned char)grim_interface_ptr->grim_is_key_active(
                    *fire_key);
                if ((unsigned char)key_state) {
                    input_primary_latch = 1;
                }
                fire_key += 216;
            } while ((int)fire_key < (int)&player_state_table[2].input.fire_key);
            if (input_primary_latch) {
                return flag;
            }
        } else {
            flag = 1;
            if (grim_interface_ptr->grim_is_mouse_button_down(0)) {
                flag = 0;
            }
            held_key = &player_state_table[0].input.fire_key;
            do {
                key_state = (unsigned char)grim_interface_ptr->grim_is_key_active(
                    *held_key);
                if ((unsigned char)key_state) {
                    flag = 0;
                }
                held_key += 216;
            } while ((int)held_key < (int)&player_state_table[2].input.fire_key);
            if (flag) {
                input_primary_latch = 0;
            }
        }
    }
    return 0;
}
