#include "crimsonland_audio.h"

extern "C" unsigned char ui_transition_direction;
extern "C" unsigned char ui_sign_crimson_update_disabled;
extern "C" game_state_id_t game_state_pending;

extern "C" void ui_menu_main_click_quit(void)
{
    game_state_pending = GAME_STATE_QUIT_TRANSITION;
    ui_sign_crimson_update_disabled = 0;
    ui_transition_direction = 0;
    sfx_mute_all(music_track_crimson_theme_id);
    sfx_mute_all(music_track_extra_0);
    sfx_mute_all(music_track_shortie_monk_id);
}
