#include "crimsonland_audio.h"

extern "C" void audio_asset_id_table_init_thunk(void)
{
    audio_asset_id_table_init();
}
