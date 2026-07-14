#include <string.h>

#include "crimsonland_audio.h"

struct dsbufferdesc8_t {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwBufferBytes;
    DWORD dwReserved;
    LPWAVEFORMATEX lpwfxFormat;
    GUID guid3DAlgorithm;
};

extern "C" unsigned char sfx_entry_create_buffers(sfx_entry_t *entry)
{
    dsbufferdesc8_t desc;
    int i;

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    desc.dwFlags = DSBCAPS_CTRLVOLUME | DSBCAPS_CTRLPAN |
        DSBCAPS_CTRLFREQUENCY | DSBCAPS_GLOBALFOCUS;
    desc.dwBufferBytes = entry->pcm_bytes;
    desc.guid3DAlgorithm = GUID_NULL;
    desc.lpwfxFormat = (WAVEFORMATEX *)entry;

    if (FAILED(dsound_iface->CreateSoundBuffer(
            (LPCDSBUFFERDESC)&desc, &entry->buffers[0], 0))) {
        return 0;
    }

    for (i = 1; i < 16; ++i) {
        if (FAILED(dsound_iface->DuplicateSoundBuffer(
                entry->buffers[0], &entry->buffers[i]))) {
            OutputDebugStringA("--- SND_  Failed to duplicate the buffer.\n");
            return 0;
        }
    }

    sfx_entry_upload_buffer(entry);
    for (i = 0; i < 16; ++i) {
        entry->buffer_in_use[i] = 0;
        entry->buffers[i]->Stop();
        entry->buffers[i]->SetCurrentPosition(0);
    }
    return 1;
}
