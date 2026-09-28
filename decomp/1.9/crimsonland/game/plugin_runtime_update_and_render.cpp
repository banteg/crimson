#include <windows.h>

#include "crimsonland_audio.h"
#include "crimsonland_mod_api.h"

extern "C" mod_interface_t *plugin_interface_ptr;
extern "C" HMODULE plugin_module_handle;
extern "C" unsigned char plugin_runtime_needs_init;
extern "C" unsigned char ui_transition_direction;
extern "C" game_state_id_t game_state_id;
extern "C" game_state_id_t game_state_pending;
extern "C" int frame_dt_ms;
extern "C" void plugin_runtime_clear_pools(void);
extern "C" void ui_elements_update_and_render(void);
extern "C" void ui_cursor_render(void);

extern "C" void plugin_runtime_update_and_render(void)
{
    mod_interface_cpp_t *plugin =
        (mod_interface_cpp_t *)plugin_interface_ptr;
    if (plugin == 0) {
        game_state_pending = GAME_STATE_MODS_MENU;
        ui_transition_direction = 0;
        ui_elements_update_and_render();
        plugin_runtime_needs_init = 1;
        return;
    }

    if (game_state_id == GAME_STATE_PLUGIN_RUNTIME
        && plugin_runtime_needs_init != 0) {
        plugin_runtime_needs_init = 0;
        plugin_runtime_active_latch = 0;
        sfx_mute_all(music_track_extra_0);
        plugin_runtime_clear_pools();
        ((mod_interface_cpp_t *)plugin_interface_ptr)->init();
        ((mod_interface_cpp_t *)plugin_interface_ptr)->parms.fields.onPause = 0;
    } else if (plugin->frame(frame_dt_ms) == 0) {
        plugin_runtime_active_latch = 0;
        ((mod_interface_cpp_t *)plugin_interface_ptr)->shutdown();
        sfx_mute_all(music_track_extra_0);
        HMODULE module = plugin_module_handle;
        plugin_interface_ptr = 0;
        FreeLibrary(module);
        plugin_module_handle = 0;
        plugin_runtime_needs_init = 1;
        game_state_pending = GAME_STATE_MODS_MENU;
        ui_transition_direction = 0;
    } else {
        plugin_runtime_active_latch = 1;
    }

    ui_elements_update_and_render();
    if (ui_transition_direction == 0
        && game_state_id == GAME_STATE_PLUGIN_RUNTIME) {
        ui_cursor_render();
        return;
    }

    plugin = (mod_interface_cpp_t *)plugin_interface_ptr;
    if (plugin != 0 && plugin_runtime_active_latch != 0
        && plugin->parms.fields.drawMouseCursor != 0) {
        ui_cursor_render();
    }
}
