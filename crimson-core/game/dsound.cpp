// DirectSound. Until the host mixer lands the device reports no driver, the
// original's own no-sound path.
#include <dsound.h>

extern "C" HRESULT WINAPI DirectSoundCreate8(LPCGUID, LPDIRECTSOUND8 *output, LPUNKNOWN) {
  *output = nullptr;
  return DSERR_NODRIVER;
}
