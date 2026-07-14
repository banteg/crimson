#include <string.h>

#include "crimsonland_mod_api.h"

struct mod_interface_prefix_t {
    void *vtable;
    mod_api_cpp_t *api;
    unsigned char draw_mouse_cursor;
    unsigned char on_pause;
};

extern "C" mod_interface_prefix_t *plugin_interface_ptr;
extern "C" unsigned char ui_transition_direction;
extern "C" int game_state_pending;

void mod_api_cpp_t::mod_api_cl_enter_menu(char *menu)
{
    if (!menu || strcmp("game_pause", menu) != 0) {
        return;
    }
    if (plugin_interface_ptr) {
        plugin_interface_ptr->on_pause = 1;
    }
    ui_transition_direction = 0;
    game_state_pending = 5;
}
