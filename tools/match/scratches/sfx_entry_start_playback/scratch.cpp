#include <stdlib.h>

#include "crimsonland_audio.h"

extern "C" int sfx_entry_start_playback(sfx_entry_t *entry)
{
    LPDIRECTSOUNDBUFFER *buffer;
    DWORD status;
    int result;

    if (entry == 0) {
        return -1;
    }

    buffer = &entry->buffers[0];
    if (dsound_restore_buffer(*buffer)) {
        if (entry->vorbis_stream == 0) {
            sfx_entry_upload_buffer(entry);
        }
    }

    result = 0;
    if (entry->vorbis_stream != 0) {
        sfx_entry_seek(entry, 0);
        music_stream_fill(entry);
        music_stream_fill(entry);
        music_stream_fill(entry);
        (*buffer)->Play(0, 0, DSBPLAY_LOOPING);
        return 0;
    }

    while (result < 16) {
        if (*buffer != 0) {
            (*buffer)->GetStatus(&status);
            if ((status & DSBSTATUS_PLAYING) == 0) {
                goto play_voice;
            }
        }
        ++result;
        ++buffer;
    }
    result = rand() % 16;
    entry->buffers[result]->Stop();

play_voice:
    entry->buffers[result]->SetFrequency(sfx_rate_scale);
    entry->buffers[result]->Play(0, 0, 0);
    return result;
}
