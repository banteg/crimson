#include "crimsonland_audio.h"

extern "C" void music_fade_out_all(int sfx_id)
{
    int other_id;

    if (!music_ready || config_blob.music_disabled ||
        config_blob.sound_disabled) {
        return;
    }

    music_playlist_randomized_latch = 0;
    for (other_id = 0; other_id < 128; ++other_id) {
        if (other_id != sfx_id && music_track_is_playing(other_id)) {
            music_fade_out_all(other_id);
        }
    }
    music_fade_out_flags[sfx_id] = 1;
}
