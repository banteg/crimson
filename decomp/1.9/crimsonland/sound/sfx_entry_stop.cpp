#include "crimsonland_audio.h"

extern "C" void sfx_entry_stop(sfx_entry_t *entry)
{
    int i;

    if (entry == 0) {
        return;
    }
    if (entry->vorbis_stream != 0) {
        if (entry->buffers[0] != 0) {
            entry->buffers[0]->Stop();
        }
        return;
    }

    for (i = 0; i < 16; ++i) {
        if (entry->buffers[i] != 0) {
            entry->buffers[i]->Stop();
        }
    }
}
