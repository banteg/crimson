// crimson.exe 1.4.0, 0x416560.
#include "overlay.h"
extern "C" char *freeware_message;
using namespace ui140;
extern "C" void game_show_message() {
    float age = freeware_simulation_clock - UI_SINCE;
    UI_FIELD(freeware_name_alpha, death_clock) = age >= 1 ? 1 : age;
    freeware_overlay_begin();
    UI_SEE_THROUGH = 0;
    scale(.65f);
    tint(1, 1, 1, 1);
    text(150, 40, "Message:");
    tint(.68f, .68f, .89f, 1);
    scale(.55f);
    text(285, 43, "(secret)");
    text(50, 400, "(press space or left mouse button)");
    tint(.85f, .85f, .85f, 1);
    scale(.65f);
    text(100, 150, UI_FIELD(freeware_message, message.c_str()));
    aim_cursor();
    if (left_click())
        set_state(3);
    if (key_pressed(0x39))
        set_state(3);
}
