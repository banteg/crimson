#include <string.h>

#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

extern "C" unsigned char wav_parse_into_entry(
    sfx_entry_t *entry,
    void *data,
    unsigned int size)
{
    unsigned int pcm_bytes;

    memset(entry, 0, sizeof(WAVEFORMATEX));
    entry->format_tag = WAVE_FORMAT_PCM;
    entry->channels = 1;
    entry->bits_per_sample = 16;
    entry->sample_rate = 22050;
    entry->block_align = 2;
    entry->cb_size = 0;
    entry->avg_bytes_per_sec = 44100;

    buffer_reader_init(data, size);
    buffer_reader_seek(0);
    if (!buffer_reader_find_tag("fmt ", 4)) {
        return 0;
    }

    buffer_reader_skip(4);
    buffer_reader_skip(2);
    entry->channels = buffer_reader_read_u16();
    entry->sample_rate = buffer_reader_read_u32();
    buffer_reader_skip(6);
    entry->bits_per_sample = buffer_reader_read_u16();
    entry->block_align =
        entry->channels * entry->bits_per_sample / 8;
    entry->cb_size = 0;
    entry->avg_bytes_per_sec = entry->block_align * entry->sample_rate;

    buffer_reader_find_tag("data", 4);
    pcm_bytes = buffer_reader_read_u32();
    entry->pcm_bytes = pcm_bytes;
    entry->pcm_data = new unsigned char[pcm_bytes];
    memcpy(
        entry->pcm_data,
        (char *)data + buffer_reader_offset,
        pcm_bytes);
    return 1;
}
