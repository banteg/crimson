#include "crimsonland_audio.h"

extern "C" void sfx_release_entry(sfx_entry_t *entry)
{
    int i;

    if (entry->vorbis_stream != 0) {
        ((vorbis_stream_t *)entry->vorbis_stream)->close();
        crt_free(entry->vorbis_stream);
        entry->vorbis_stream = 0;
        if (entry->buffers[0] != 0) {
            entry->buffers[0]->Release();
        }
        entry->buffers[0] = 0;
        crt_free(entry->pcm_data);
        entry->pcm_data = 0;
        return;
    }

    for (i = 15; i >= 0; --i) {
        if (entry->buffers[i] != 0) {
            entry->buffers[i]->Release();
        }
        entry->buffers[i] = 0;
    }
    crt_free(entry->pcm_data);
    entry->pcm_data = 0;
}
