#include "crimsonland_audio.h"

extern "C" void sfx_mute_all(int sfx_id)
{
    int other_id;

    if (!sfx_unmuted_flag || config_blob.music_disabled ||
        config_blob.sound_disabled) {
        return;
    }

    music_playlist_randomized_latch = 0;
    for (other_id = 0; other_id < 128; ++other_id) {
        if (other_id != sfx_id && sfx_is_unmuted(other_id)) {
            sfx_mute_all(other_id);
        }
    }
    sfx_mute_flags[sfx_id] = 1;
}
