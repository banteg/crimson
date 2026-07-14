#include <stdio.h>
#include <string.h>

#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

extern "C" unsigned char sfx_entry_load_ogg(
    sfx_entry_t *entry,
    char *path)
{
    unsigned int size;
    vorbis_stream_t stream;
    unsigned char *buffer;
    unsigned int remaining;
    int read_bytes;

    if (!resource_open_read(path, &size)) {
        return 0;
    }

    FILE *fp = resource_fp;
    buffer = new unsigned char[size + 8];
    fread(buffer + 8, size, 1, fp);
    resource_close();

    if (!stream.open(buffer, size)) {
        return 0;
    }

    memset(entry, 0, sizeof(WAVEFORMATEX));
    entry->channels = stream.channels;
    entry->format_tag = WAVE_FORMAT_PCM;
    entry->block_align = entry->channels * 16 / 8;
    entry->avg_bytes_per_sec = entry->block_align * stream.sample_rate;
    entry->sample_rate = stream.sample_rate;
    entry->bits_per_sample = 16;
    entry->cb_size = 0;
    entry->pcm_bytes = stream.total_pcm_bytes;
    entry->pcm_data = new unsigned char[entry->pcm_bytes];

    remaining = entry->pcm_bytes;
    read_bytes = 1;
    while (remaining > 0 && read_bytes != 0) {
        read_bytes = stream.read_pcm16(
            (char *)(entry->pcm_bytes - remaining +
                (unsigned int)entry->pcm_data),
            remaining);
        remaining -= read_bytes;
    }

    stream.close();
    if (sfx_entry_create_buffers(entry)) {
        return 1;
    }
    return 0;
}
