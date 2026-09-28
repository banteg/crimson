#include "crimsonland_audio.h"

extern "C" void audio_suspend_channels(void)
{
    int i;

    if (!sfx_unmuted_flag
        || config_blob.music_disabled
        || config_blob.sound_disabled) {
        return;
    }

    for (i = 0; i < 128; i++) {
        sfx_entry_stop(&music_entry_table[i]);
    }
}
