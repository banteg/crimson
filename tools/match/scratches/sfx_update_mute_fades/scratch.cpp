#include "crimsonland_audio.h"

extern "C" void sfx_update_mute_fades(void)
{
    int i;
    float volume;
    DWORD status;

    if (audio_suspend_flag || !sfx_unmuted_flag) {
        return;
    }

    for (i = 0; i < 128; ++i) {
        music_entry_t *entry = &music_entry_table[i];

        if (entry->vorbis_stream == 0) {
            continue;
        }

        if (config_blob.music_volume <= 0.0f) {
            entry->buffers[0]->Stop();
        } else {
            if (!sfx_mute_flags[i]) {
                entry->buffers[0]->GetStatus(&status);
                if ((status & DSBSTATUS_PLAYING) == 0) {
                    console_printf(
                        &console_log_queue,
                        "SND: detected unsilenced hearable tune not playing -- starting up..\n");
                    sfx_entry_resume(entry);
                }
            }
        }

        if (sfx_mute_flags[i]) {
            if (sfx_volume_table[i] > 0.0f) {
                volume = sfx_volume_table[i] - frame_dt * 0.5f;
                sfx_volume_table[i] = volume;
                if (volume <= 0.0f) {
                    sfx_entry_stop(entry);
                } else {
                    sfx_entry_set_volume(entry, volume);
                }
            }
            if (sfx_volume_table[i] < 0.0f) {
                sfx_volume_table[i] = 0.0f;
            }
        } else if (sfx_volume_table[i] < config_blob.music_volume) {
            volume = sfx_volume_table[i] + frame_dt;
            sfx_volume_table[i] = volume;
            if (volume < config_blob.music_volume) {
                sfx_entry_set_volume(entry, volume);
            } else {
                sfx_entry_set_volume(entry, config_blob.music_volume);
            }
        } else if (sfx_volume_table[i] > config_blob.music_volume) {
            sfx_entry_set_volume(
                entry,
                sfx_volume_table[i] = config_blob.music_volume);
        }
    }
}
