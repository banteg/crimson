#include "crimsonland_audio.h"

int vorbis_stream_t::pcm_seek(unsigned int sample_offset)
{
    return ov_pcm_seek(&file, sample_offset);
}
