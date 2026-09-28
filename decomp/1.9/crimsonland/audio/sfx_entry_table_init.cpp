#include "crimsonland_audio.h"

extern "C" void sfx_entry_table_init(void)
{
    int i;
    sfx_entry_cpp_t *entry;

    entry = (sfx_entry_cpp_t *)&sfx_entry_table[0];
    for (i = 128; i != 0; --i) {
        entry->reset_runtime_state();
        ++entry;
    }
}
