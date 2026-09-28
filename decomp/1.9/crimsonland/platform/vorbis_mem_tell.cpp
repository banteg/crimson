#include "crimsonland_audio.h"

extern "C" long vorbis_mem_tell(void *datasource)
{
    vorbis_memory_source_t *source =
        (vorbis_memory_source_t *)((unsigned char *)datasource - 8);
    return source->cursor;
}
