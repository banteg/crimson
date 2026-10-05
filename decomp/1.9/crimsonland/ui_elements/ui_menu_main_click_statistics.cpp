#include "crimsonland_audio.h"

extern "C" unsigned char ui_transition_direction;
extern "C" game_state_id_t game_state_pending;

extern "C" void ui_menu_main_click_statistics(void)
{
    ui_transition_direction = 0;
    game_state_pending = GAME_STATE_STATISTICS_MENU;
    music_fade_out_all(music_track_crimson_theme_id);
    music_fade_out_all(music_track_shortie_monk_id);
    music_fade_out_all(music_track_game_playlist);
    music_play_exclusive(music_track_shortie_monk_id);
}
