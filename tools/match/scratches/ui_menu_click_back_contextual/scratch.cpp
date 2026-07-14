#include "crimsonland_audio.h"

extern "C" unsigned char ui_transition_direction;
extern "C" unsigned char render_pass_mode;
extern "C" game_state_id_t game_state_pending;

extern "C" void ui_menu_click_back_contextual(void)
{
    ui_transition_direction = 0;
    if (plugin_runtime_active_latch) {
        game_state_pending = GAME_STATE_PAUSE_MENU;
    } else {
        game_state_pending = render_pass_mode
            ? GAME_STATE_PAUSE_MENU
            : GAME_STATE_MAIN_MENU;
    }
}
