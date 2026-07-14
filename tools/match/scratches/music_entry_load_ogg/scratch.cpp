#include <stdio.h>
#include <string.h>

#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

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
        ((vorbis_stream_t *)entry->vorbis_stream)->channels;
    entry->sample_rate =
        ((vorbis_stream_t *)entry->vorbis_stream)->sample_rate;
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
