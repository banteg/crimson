#include "crimsonland_gameplay.h"

extern "C" void audio_shutdown_all(void)
{
    sfx_release_all();
    music_release_all();
    dsound_shutdown();
}
