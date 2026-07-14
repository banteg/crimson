#include "crimsonland_audio.h"

extern "C" void music_stream_update(music_entry_t *entry)
{
    DWORD cursor;
    unsigned int delta;
    unsigned int quarter_bytes;

    if (FAILED(entry->buffers[0]->GetCurrentPosition(&cursor, 0))) {
        return;
    }

    if (cursor < entry->stream_fill_bytes) {
        delta = entry->pcm_bytes - entry->stream_fill_bytes + cursor;
    } else {
        delta = cursor - entry->stream_fill_bytes;
    }
    entry->stream_fill_bytes = cursor;
    entry->stream_total_bytes += delta;
    entry->stream_cursor_bytes += delta;

    quarter_bytes = (int)entry->pcm_bytes / 4;
    if (entry->stream_cursor_bytes > quarter_bytes) {
        entry->stream_cursor_bytes -= quarter_bytes;
        music_stream_fill(entry);
    }
}
