#include "crimsonland_gameplay.h"

extern "C" unsigned char game_core_init(void)
{
    console_printf(&console_log_queue, "GDI initializing UI elements.\n");
    quest_database_init();
    effect_defaults_reset();
    ui_menu_assets_init();
    bonus_metadata_init();
    render_pass_mode = 0;
    game_state_set(GAME_STATE_MAIN_MENU);
    console_printf(&console_log_queue, "Core Init done.\n");
    return 1;
}
