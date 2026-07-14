#include "crimsonland_audio.h"

extern "C" unsigned char dsound_restore_buffer(LPDIRECTSOUNDBUFFER buffer)
{
    DWORD status;

    if (buffer != 0 && SUCCEEDED(buffer->GetStatus(&status)) &&
        (status & DSBSTATUS_BUFFERLOST) != 0) {
        HRESULT result;
        do {
            result = buffer->Restore();
            if (result == DSERR_BUFFERLOST) {
                Sleep(10);
            }
        } while (result != DS_OK);
        OutputDebugStringA("--- SND_  Buffer restored.\n");
        return 1;
    }
    return 0;
}
