#include "crimsonland_audio.h"

extern "C" void sfx_entry_seek(sfx_entry_t *entry, unsigned int sample_offset)
{
    if (entry->vorbis_stream == 0) {
        return;
    }

    entry->buffers[0]->SetCurrentPosition(sample_offset);
    ((vorbis_stream_t *)entry->vorbis_stream)->pcm_seek(sample_offset);
    entry->stream_cursor = 0;
    entry->stream_fill_bytes = 0;
    entry->stream_total_bytes = 0;
    entry->stream_cursor_bytes = 0;
}
