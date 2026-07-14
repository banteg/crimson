#include "crimsonland_gameplay.h"

extern "C" unsigned char ui_transition_direction;
extern "C" game_state_id_t game_state_pending;

extern "C" void ui_menu_main_click_options(void)
{
    ui_transition_direction = 0;
    game_state_pending = GAME_STATE_OPTIONS_MENU;
}
