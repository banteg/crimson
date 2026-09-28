#include "crimsonland_audio.h"

void vorbis_stream_t::close(void)
{
    crt_free(memory_source);
    ov_clear(&file);
}
