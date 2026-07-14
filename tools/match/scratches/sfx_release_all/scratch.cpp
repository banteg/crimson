#include "crimsonland_audio.h"

extern "C" void sfx_release_all(void)
{
    sfx_entry_t *entry;

    if (config_blob.sound_disabled) {
        return;
    }
    entry = &sfx_entry_table[0];
    while ((int)entry < (int)&sfx_entry_table[128]) {
        sfx_release_entry(entry);
        ++entry;
    }
    console_printf(&console_log_queue, "SFX_Shutdown ()\n");
    console_printf(&console_log_queue, "SFX Released.\n");
    console_log_queue.flush_log("console.log");
}
