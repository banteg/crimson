#include "crimsonland_audio.h"

extern "C" int vorbis_mem_close_callback(void *datasource)
{
    return 1;
}
