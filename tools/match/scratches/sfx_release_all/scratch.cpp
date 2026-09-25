#include "crimsonland_audio.h"

extern "C" void sfx_release_all(void)
{
    int i;

    if (config_blob.sound_disabled) {
        return;
    }
    for (i = 0; i < 128; i++) {
        sfx_release_entry(&sfx_entry_table[i]);
    }
    console_printf(&console_log_queue, "SFX_Shutdown ()\n");
    console_printf(&console_log_queue, "SFX Released.\n");
    console_log_queue.flush_log("console.log");
}
