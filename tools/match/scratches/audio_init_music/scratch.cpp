#include <string.h>

#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

extern "C" void audio_init_music(void)
{
    int track_id;

    if (config_blob.sound_disabled || config_blob.music_disabled) {
        return;
    }

    memset(sfx_mute_flags, 1, sizeof(sfx_mute_flags));
    memset(sfx_volume_table, 0, sizeof(sfx_volume_table));

    audio_resource_pack_available = resource_pack_set("music.paq");
    if (audio_resource_pack_available) {
        console_printf(
            &console_log_queue,
            "...set sound resource paq 'music.paq'\n");
    } else {
        console_printf(
            &console_log_queue,
            "...resource paq 'music.paq' not found, using separate files.\n");
    }

    music_track_intro_id = music_load_track("music\\intro.ogg");
    music_track_shortie_monk_id =
        music_load_track("music\\shortie_monk.ogg");
    console_log_queue.exec_line("exec music\\game_tunes.txt");
    music_track_crimson_theme_id =
        music_load_track("music\\crimson_theme.ogg");
    track_id = music_load_track("music\\crimsonquest.ogg");
    music_track_crimsonquest_id = track_id;
    music_track_extra_0 = track_id + 1;
    music_track_extra_1 = track_id + 2;
    sfx_unmuted_flag = 1;
}
