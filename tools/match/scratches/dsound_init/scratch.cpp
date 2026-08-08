#include <string.h>

#include "crimsonland_audio.h"

extern "C" unsigned char dsound_init(
    HWND hwnd,
    DWORD coop_level,
    int channels,
    DWORD sample_rate,
    int bits_per_sample)
{
    LPDIRECTSOUNDBUFFER primary_buffer;
    WAVEFORMATEX wave_format;
    dsbufferdesc8_t desc;

    if (dsound_iface != 0) {
        dsound_iface->Release();
    }
    dsound_iface = 0;

    if (FAILED(DirectSoundCreate8(
            0,
            (LPDIRECTSOUND8 *)&dsound_iface,
            0))) {
        return 0;
    }
    if (FAILED(dsound_iface->SetCooperativeLevel(hwnd, coop_level))) {
        return 0;
    }

    memset(&desc, 0, sizeof(desc));
    primary_buffer = 0;
    desc.dwSize = sizeof(desc);
    desc.dwFlags = DSBCAPS_PRIMARYBUFFER;
    desc.dwBufferBytes = 0;
    desc.lpwfxFormat = 0;
    if (FAILED(dsound_iface->CreateSoundBuffer(
            (LPCDSBUFFERDESC)&desc,
            &primary_buffer,
            0))) {
        return 0;
    }

    memset(&wave_format, 0, sizeof(wave_format));
    wave_format.wFormatTag = WAVE_FORMAT_PCM;
    wave_format.nChannels = (WORD)channels;
    wave_format.nSamplesPerSec = sample_rate;
    wave_format.wBitsPerSample = bits_per_sample;
    wave_format.nBlockAlign = ((WORD)bits_per_sample >> 3) * channels;
    wave_format.nAvgBytesPerSec =
        wave_format.nBlockAlign * wave_format.nSamplesPerSec;

    if (FAILED(primary_buffer->SetFormat(&wave_format))) {
        return 0;
    }
    if (primary_buffer != 0) {
        primary_buffer->Release();
    }
    return 1;
}
