#include "crimsonland_audio.h"

extern "C" void audio_suspend_channels(void)
{
    music_entry_t *entry;

    if (!sfx_unmuted_flag
        || config_blob.music_disabled
        || config_blob.sound_disabled) {
        return;
    }

    entry = &music_entry_table[0];
    while ((int)entry < (int)&music_entry_table[128]) {
        sfx_entry_stop(entry);
        ++entry;
    }
}
