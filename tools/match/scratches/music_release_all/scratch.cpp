#include "crimsonland_audio.h"

extern "C" void music_release_all(void)
{
    music_entry_t *entry;

    if (!sfx_unmuted_flag) {
        return;
    }
    entry = &music_entry_table[0];
    while ((int)entry < (int)&music_entry_table[128]) {
        sfx_release_entry(entry);
        ++entry;
    }
    console_log_queue.flush_log("console.log");
}
