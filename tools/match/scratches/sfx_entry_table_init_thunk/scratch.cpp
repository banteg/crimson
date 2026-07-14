#include "crimsonland_audio.h"

extern "C" void sfx_entry_table_init_thunk(void)
{
    sfx_entry_table_init();
}
