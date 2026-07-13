#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" int input_primary_is_down(void)
{
    if (!grim_interface_ptr->grim_is_mouse_button_down(0)
        && !(unsigned char)grim_interface_ptr->grim_is_key_active(
            player_state_table[0].input.fire_key)
        && !(unsigned char)grim_interface_ptr->grim_is_key_active(
            player_state_table[1].input.fire_key)) {
        return 0;
    }
    return 1;
}
