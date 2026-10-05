#include "crimsonland_audio.h"

extern "C" void music_update_fades(void)
{
    int i;
    DWORD status;

    if (audio_suspend_flag || !music_ready) {
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
            if (!music_fade_out_flags[i]) {
                entry->buffers[0]->GetStatus(&status);
                if ((status & DSBSTATUS_PLAYING) == 0) {
                    console_printf(
                        &console_log_queue,
                        "SND: detected unsilenced hearable tune not playing -- starting up..\n");
                    sfx_entry_resume(entry);
                }
            }
        }

        if (music_fade_out_flags[i]) {
            if (music_track_volume[i] > 0.0f) {
                music_track_volume[i] -= frame_dt * 0.5f;
                if (music_track_volume[i] <= 0.0f) {
                    sfx_entry_stop(entry);
                } else {
                    sfx_entry_set_volume(entry, music_track_volume[i]);
                }
            }
            if (music_track_volume[i] < 0.0f) {
                music_track_volume[i] = 0.0f;
            }
        } else if (music_track_volume[i] < config_blob.music_volume) {
            music_track_volume[i] += frame_dt;
            if (music_track_volume[i] >= config_blob.music_volume) {
                sfx_entry_set_volume(entry, config_blob.music_volume);
            } else {
                sfx_entry_set_volume(entry, music_track_volume[i]);
            }
        } else if (music_track_volume[i] > config_blob.music_volume) {
            music_track_volume[i] = config_blob.music_volume;
            sfx_entry_set_volume(entry, music_track_volume[i]);
        }
    }
}
