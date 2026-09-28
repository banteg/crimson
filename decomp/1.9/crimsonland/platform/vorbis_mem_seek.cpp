#include "crimsonland_audio.h"

extern "C" int vorbis_mem_seek(
    void *datasource,
    ogg_int64_t offset,
    int whence)
{
    vorbis_memory_source_t *source =
        (vorbis_memory_source_t *)((unsigned char *)datasource - 8);
    unsigned int distance = (unsigned int)offset;

    if (whence == SEEK_SET) {
        source->cursor = distance;
        return 1;
    }
    if (whence == SEEK_END) {
        source->cursor = source->size - distance;
        return 1;
    }
    source->cursor += distance;
    return 1;
}
