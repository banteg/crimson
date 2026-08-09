#include "crimsonland_audio.h"

extern "C" void sfx_entry_set_volume(sfx_entry_t *entry, float volume)
{
    int i;
    LPDIRECTSOUNDBUFFER *buffer;

    volume = (volume + 2.0f) * (1.0f / 3.0f);
    if (entry->vorbis_stream != 0 && entry->volume == volume) {
        return;
    }

    i = 0;
    entry->volume = volume;
    buffer = entry->buffers;
    for (; i < 16; ++i, ++buffer) {
        if (*buffer != 0) {
            (*buffer)->SetVolume((long)((1.0f - volume) * -10000.0f));
            if (entry->vorbis_stream != 0) {
                break;
            }
        }
    }
}
