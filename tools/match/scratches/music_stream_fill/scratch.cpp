#include "crimsonland_audio.h"

extern "C" unsigned char music_stream_fill(music_entry_t *entry)
{
    void *dst1;
    DWORD dst1_bytes;
    void *dst2;
    DWORD dst2_bytes;
    int remaining;
    int read_bytes;

    dst1 = 0;
    dst2 = 0;

    if (FAILED(entry->buffers[0]->Lock(
            entry->stream_cursor,
            (int)entry->pcm_bytes / 4,
            &dst1,
            &dst1_bytes,
            &dst2,
            &dst2_bytes,
            0))) {
        return 0;
    }
    if (dst2 != 0) {
        OutputDebugStringA(
            "--- SND_  Somehow data on the second lock too! This can't be happening!.\n");
        return 0;
    }

    remaining = dst1_bytes;
    do {
        read_bytes = ((vorbis_stream_t *)entry->vorbis_stream)->read_pcm16(
            (dst1_bytes - remaining) + (char *)dst1,
            remaining);
        if (read_bytes <= 0) {
            read_bytes = ((vorbis_stream_t *)entry->vorbis_stream)->read_pcm16(
                (dst1_bytes - remaining) + (char *)dst1,
                remaining);
        }
        remaining -= read_bytes;
    } while (remaining > 0 && read_bytes != 0);

    entry->buffers[0]->Unlock(dst1, dst1_bytes, 0, 0);
    dst1_bytes += entry->stream_cursor;
    entry->stream_cursor = (int)dst1_bytes % (int)entry->pcm_bytes;
    return 0;
}
