#include "crimsonland_audio.h"

extern "C" void sfx_play_exclusive(int sfx_id)
{
    int i;
    music_entry_t *entry;

    if (!sfx_unmuted_flag || config_blob.music_disabled ||
        config_blob.sound_disabled) {
        return;
    }

    if (!plugin_runtime_active_latch) {
        if (sfx_id == music_track_extra_0) {
            if (music_playlist_randomized_latch ||
                music_playlist_entry_count == 0) {
                return;
            }
            sfx_id =
                music_playlist[crt_rand() % music_playlist_entry_count];
            music_playlist_randomized_latch = 1;
        } else {
            music_playlist_randomized_latch = 0;
        }
    }

    for (i = 0; i < 128; ++i) {
        if (i != sfx_id && sfx_is_unmuted(i)) {
            sfx_mute_all(i);
        }
    }

    if (sfx_volume_table[sfx_id] <= 0.0f) {
        entry = &music_entry_table[sfx_id];
        sfx_entry_start_playback(entry);
        sfx_entry_set_volume(entry, config_blob.music_volume);
        sfx_mute_flags[sfx_id] = 0;
        sfx_volume_table[sfx_id] = config_blob.music_volume;
    }
}
