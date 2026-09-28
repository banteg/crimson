#include <string.h>

#include "crimsonland_audio.h"

extern "C" void audio_asset_id_table_init(void)
{
    memset(audio_asset_id_table, 0, sizeof(audio_asset_id_table));
}
