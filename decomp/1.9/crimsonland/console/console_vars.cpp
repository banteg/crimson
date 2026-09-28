#include "crimsonland_console.h"

extern "C" void console_vars(void)
{
    int count = 0;
    console_cvar_entry_t *entry = console_log_queue.cvar_head;
    while (entry) {
        console_printf(&console_log_queue, "%s\n", entry->name);
        entry = entry->next;
        ++count;
    }
    console_printf(&console_log_queue, "%i variables\n", count);
}
