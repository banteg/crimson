#include <stdio.h>
#include <string.h>

#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

#if CL_BUILD == 10908
/*
 * Translation-unit context for 1.9.8. Its C2 (9044) reuses what it learned
 * compiling earlier functions of the same unit: resource_open_read precedes
 * this function there (see resource/resource_open_read.cpp), so the resource
 * size stays in a register across the allocation, read and close calls.
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

extern "C" unsigned char music_entry_load_ogg(
    music_entry_t *entry,
    char *path)
{
    unsigned int size;
    unsigned char *buffer;
    dsbufferdesc8_t desc;

    if (!resource_open_read(path, &size)) {
        return 0;
    }

    FILE *fp = resource_fp;
    buffer = new unsigned char[size + 8];
    fread(buffer + 8, size, 1, fp);
    resource_close();

    entry->vorbis_stream = new vorbis_stream_t;
    if (!((vorbis_stream_t *)entry->vorbis_stream)->open(buffer, size)) {
        return 0;
    }

    memset(entry, 0, sizeof(WAVEFORMATEX));
    entry->format_tag = WAVE_FORMAT_PCM;
    entry->channels =
        ((vorbis_stream_t *)entry->vorbis_stream)->info.channels;
    entry->sample_rate =
        ((vorbis_stream_t *)entry->vorbis_stream)->info.rate;
    entry->bits_per_sample = 16;
    entry->block_align = entry->channels * 16 / 8;
    entry->cb_size = 0;
    entry->avg_bytes_per_sec = entry->block_align * entry->sample_rate;
    entry->pcm_bytes = entry->avg_bytes_per_sec * 2;
    entry->pcm_data = new unsigned char[entry->pcm_bytes];
    memset(entry->pcm_data, 0, entry->pcm_bytes);

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    desc.dwFlags = DSBCAPS_CTRLVOLUME | DSBCAPS_CTRLPAN |
        DSBCAPS_GLOBALFOCUS | DSBCAPS_GETCURRENTPOSITION2;
    desc.dwBufferBytes = entry->pcm_bytes;
    desc.guid3DAlgorithm = GUID_NULL;
    desc.lpwfxFormat = (WAVEFORMATEX *)entry;

    if (FAILED(dsound_iface->CreateSoundBuffer(
            (LPCDSBUFFERDESC)&desc, &entry->buffers[0], 0))) {
        return 0;
    }
    entry->stream_cursor_bytes = 0;
    return 1;
}
