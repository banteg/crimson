#include "crimsonland_audio.h"

extern "C" void music_release_all(void)
{
    int i;

    if (!sfx_unmuted_flag) {
        return;
    }
    for (i = 0; i < 128; i++) {
        sfx_release_entry(&music_entry_table[i]);
    }
    console_log_queue.flush_log("console.log");
}
