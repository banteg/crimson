#include <stdio.h>
#include <string.h>

#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

#if CL_BUILD == 10908
/*
 * Translation-unit context for 1.9.8. Its C2 (9044) reuses what it learned
 * compiling earlier functions of the same unit: resource_open_read precedes
 * this function there (see resource/resource_open_read.cpp), so the resource
 * size stays in esi across the allocation, read and close calls.
 * 1.9.93's C2 (8966) ignores this, so the canonical object keeps one function
 * per file.
 */
unsigned char resource_open_read(char *path, unsigned int *size_out)
{
    if (resource_pack_enabled) {
        FILE *fp;

        resource_fp = fopen(resource_pack_path_buf, "rb");
        if (resource_fp == 0) {
            return 0;
        }

        fp = resource_fp;
        fseek(fp, 4, SEEK_SET);
        while (resource_pack_read_cstring(fp)) {
            unsigned int entry_size;

            fread(&entry_size, sizeof(entry_size), 1, fp);
            *size_out = entry_size;
            if (_stricmp(resource_pack_entry_name_buf, path) == 0) {
                return 1;
            }
            fseek(fp, entry_size, SEEK_CUR);
        }
        fclose(fp);
    }

    resource_fp = fopen(path, "rb");
    if (resource_fp == 0) {
        return 0;
    }
    fseek(resource_fp, 0, SEEK_END);
    *size_out = ftell(resource_fp);
    fseek(resource_fp, 0, SEEK_SET);
    return 1;
}
#endif

struct sfx_pcm_storage_t {
    void *data;
    unsigned int bytes;
};

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
    entry->channels = stream.info.channels;
    entry->format_tag = WAVE_FORMAT_PCM;
    entry->block_align = entry->channels * 16 / 8;
    entry->avg_bytes_per_sec = entry->block_align * stream.info.rate;
    entry->sample_rate = stream.info.rate;
    entry->bits_per_sample = 16;
    entry->cb_size = 0;
    entry->pcm_bytes = stream.total_pcm_bytes;
    entry->pcm_data = new unsigned char[entry->pcm_bytes];

    remaining = entry->pcm_bytes;
    read_bytes = 1;
    while (remaining > 0 && read_bytes != 0) {
        sfx_pcm_storage_t &pcm =
            *(sfx_pcm_storage_t *)&entry->pcm_data;
        read_bytes = stream.read_pcm16(
            (pcm.bytes - remaining) + (char *)pcm.data,
            remaining);
        remaining -= read_bytes;
    }

    stream.close();
    if (sfx_entry_create_buffers(entry)) {
        return 1;
    }
    return 0;
}
