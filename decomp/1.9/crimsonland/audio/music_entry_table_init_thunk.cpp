#include "crimsonland_audio.h"

extern "C" void music_entry_table_init_thunk(void)
{
    music_entry_table_init();
}
