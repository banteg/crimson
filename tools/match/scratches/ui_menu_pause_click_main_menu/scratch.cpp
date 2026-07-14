#include <windows.h>

#include "crimsonland_audio.h"

class mod_interface_cpp_t {
public:
    virtual unsigned char init(void);
    virtual void shutdown(void);
    virtual unsigned char frame(int frame_dt_ms);

    void *api;
    mod_parms_t parms;
};

extern "C" mod_interface_t *plugin_interface_ptr;
extern "C" HMODULE plugin_module_handle;
extern "C" unsigned char plugin_runtime_needs_init;
extern "C" unsigned char ui_transition_direction;
extern "C" unsigned char render_pass_mode;
extern "C" game_state_id_t game_state_pending;

extern "C" void ui_menu_pause_click_main_menu(void)
{
    if (plugin_interface_ptr != 0) {
        ((mod_interface_cpp_t *)plugin_interface_ptr)->parms.fields.onPause = 0;
        plugin_runtime_active_latch = 0;
        ((mod_interface_cpp_t *)plugin_interface_ptr)->shutdown();
        sfx_mute_all(music_track_extra_0);
        HMODULE module = plugin_module_handle;
        plugin_interface_ptr = 0;
        FreeLibrary(module);
        plugin_module_handle = 0;
        plugin_runtime_needs_init = 1;
        game_state_pending = GAME_STATE_MODS_MENU;
    } else {
        game_state_pending = GAME_STATE_MAIN_MENU;
    }

    ui_transition_direction = 0;
    render_pass_mode = 0;
    sfx_mute_all(music_track_crimson_theme_id);
    sfx_mute_all(music_track_shortie_monk_id);
    sfx_mute_all(music_track_extra_0);
    sfx_play_exclusive(music_track_crimson_theme_id);
}
