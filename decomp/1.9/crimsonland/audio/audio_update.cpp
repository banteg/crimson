#include "crimsonland_audio.h"

extern "C" void audio_update(void)
{
    int i;

    if (config_blob.sound_disabled) {
        return;
    }

    for (i = 0; i < 128; ++i) {
        if (sfx_cooldown_table[i] > 0.0f) {
            sfx_cooldown_table[i] -= frame_dt_copy;
        }
    }

    if (!sfx_unmuted_flag) {
        return;
    }
    for (i = 0; i < 128; ++i) {
        if (music_entry_table[i].vorbis_stream != 0) {
            music_stream_update(&music_entry_table[i]);
        }
    }
    sfx_update_mute_fades();
}
