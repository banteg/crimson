#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" void game_update_generic_menu(void)
{
    if (render_pass_mode || game_state_id == GAME_STATE_PAUSE_MENU) {
        gameplay_render_world();
    } else {
        terrain_render();
    }

    grim_interface_ptr->grim_draw_fullscreen_color(
        0.0f, 0.0f, 0.0f, screen_fade_alpha);
    ui_elements_update_and_render();
    perk_prompt_update_and_render();
    ui_cursor_render();
}
