#include "crimsonland_audio.h"

unsigned char vorbis_stream_t::open(void *buffer, unsigned int size)
{
    callbacks.read_func = vorbis_mem_read;
    callbacks.seek_func = vorbis_mem_seek;
    callbacks.close_func = vorbis_mem_close_callback;
    callbacks.tell_func = vorbis_mem_tell;
    bitstream = 0;
    memory_source = buffer;

    ((vorbis_memory_source_t *)memory_source)->size = size;
    ((vorbis_memory_source_t *)memory_source)->cursor = 0;

    if (ov_open_callbacks(
            ((vorbis_memory_source_t *)memory_source)->data,
            &file,
            0,
            0,
            callbacks) < 0) {
        crt_printf("Input does not appear to be an Ogg bitstream.\n");
        return 0;
    }

    info = *ov_info(&file, -1);
    total_pcm_bytes =
        (unsigned int)(ov_pcm_total(&file, -1) * info.channels * 16 / 8);
    source_data_offset = vorbis_mem_tell(
        ((vorbis_memory_source_t *)memory_source)->data);
    return 1;
}
