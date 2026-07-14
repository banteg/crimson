#include "crimsonland_audio.h"

sfx_entry_cpp_t *sfx_entry_cpp_t::reset_runtime_state(void)
{
    int i;

    stream_cursor_bytes = 0;
    stream_total_bytes = 0;
    stream_fill_bytes = 0;
    vorbis_stream = 0;
    pcm_data = 0;
    pcm_bytes = 0;
    stream_cursor = 0;
    volume = -1.0f;

    for (i = 15; i >= 0; --i) {
        buffers[i] = 0;
    }
    return this;
}
