#include "crimsonland_audio.h"

extern "C" void sfx_entry_resume(sfx_entry_t *entry)
{
    if (entry->vorbis_stream != 0) {
        entry->buffers[0]->Play(0, 0, DSBPLAY_LOOPING);
    }
}
