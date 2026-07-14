#include "crimsonland_audio.h"

extern "C" void music_entry_table_init(void)
{
    int i;
    sfx_entry_cpp_t *entry;

    entry = (sfx_entry_cpp_t *)&music_entry_table[0];
    for (i = 128; i != 0; --i) {
        entry->reset_runtime_state();
        ++entry;
    }
}
