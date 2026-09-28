#include "crimsonland_audio.h"

int vorbis_stream_t::read_pcm16(void *dst, int bytes)
{
    int result = ov_read(&file, (char *)dst, bytes, 0, 2, 1, &bitstream);
    if (result == 0) {
        return result;
    }
    return result < 0 ? 0 : result;
}
