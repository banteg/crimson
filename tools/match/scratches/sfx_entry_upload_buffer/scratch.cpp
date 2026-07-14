#include <string.h>

#include "crimsonland_audio.h"

extern "C" unsigned char sfx_entry_upload_buffer(sfx_entry_t *entry)
{
    void *dst;
    DWORD dst_bytes;
    HRESULT result;

    result = entry->buffers[0]->Lock(
        0,
        entry->pcm_bytes,
        &dst,
        &dst_bytes,
        0,
        0,
        0);
    if (FAILED(result) && result == DSERR_BUFFERLOST) {
        if (!dsound_restore_buffer(entry->buffers[0])) {
            return 0;
        }
    }

    memcpy(dst, entry->pcm_data, entry->pcm_bytes);
    entry->buffers[0]->Unlock(dst, dst_bytes, 0, 0);
    return 1;
}
