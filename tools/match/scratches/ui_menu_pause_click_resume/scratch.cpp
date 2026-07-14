#include "crimsonland_audio.h"

struct mod_interface_prefix_t {
    void *vtable;
    void *api;
    unsigned char draw_mouse_cursor;
    unsigned char on_pause;
};

extern "C" mod_interface_prefix_t *plugin_interface_ptr;
extern "C" unsigned char ui_transition_direction;
extern "C" unsigned char ui_sign_crimson_update_disabled;
extern "C" game_state_id_t game_state_pending;
extern "C" game_mode_id_t config_game_mode;

extern "C" void ui_menu_pause_click_resume(void)
{
    if (plugin_interface_ptr) {
        plugin_interface_ptr->on_pause = 0;
    }
    ui_sign_crimson_update_disabled = 0;
    ui_transition_direction = 0;
    game_state_pending = plugin_runtime_active_latch
        ? GAME_STATE_PLUGIN_RUNTIME
        : GAME_STATE_GAMEPLAY;
    if (config_game_mode == GAME_MODE_TYPO_SHOOTER) {
        game_state_pending = GAME_STATE_TYPO_GAMEPLAY;
    }
}
