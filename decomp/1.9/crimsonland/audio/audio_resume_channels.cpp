#include "crimsonland_audio.h"

extern "C" void audio_resume_channels(void)
{
    music_entry_t *entry;
    int index;

    if (!sfx_unmuted_flag
        || config_blob.music_disabled
        || config_blob.sound_disabled) {
        return;
    }

    for (index = 0; index < 128; ++index) {
        entry = &music_entry_table[index];
        if (sfx_mute_flags[index] == 0) {
            sfx_entry_resume(entry);
        }
    }
}
