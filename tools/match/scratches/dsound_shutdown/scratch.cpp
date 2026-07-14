#include "crimsonland_audio.h"

extern "C" void dsound_shutdown(void)
{
    if (dsound_iface != 0) {
        dsound_iface->Release();
    }
    dsound_iface = 0;
}
