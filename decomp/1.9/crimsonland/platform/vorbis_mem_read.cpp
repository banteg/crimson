#include <string.h>

#include "crimsonland_audio.h"

extern "C" unsigned int vorbis_mem_read(
    void *dst,
    unsigned int size,
    unsigned int count,
    void *datasource)
{
    unsigned int *cursor =
        (unsigned int *)((unsigned char *)datasource - 4);
    unsigned int *source_size =
        (unsigned int *)((unsigned char *)datasource - 8);

    if (*cursor >= *source_size) {
        *cursor = 0;
    }

    unsigned int copied;
    if (*source_size < size * count + *cursor) {
        copied = *source_size - *cursor;
    } else {
        copied = size * count;
    }

    memcpy(dst, (unsigned char *)datasource + *cursor, copied);
    *cursor += size * count;
    return copied;
}
