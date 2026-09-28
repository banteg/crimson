#include "crimsonland_console.h"

extern "C" void console_cmdlist(void)
{
    int count = 0;
    console_command_entry_t *entry = console_log_queue.command_head;
    while (entry) {
        console_printf(&console_log_queue, "%s\n", entry->name);
        entry = entry->next;
        ++count;
    }
    console_printf(&console_log_queue, "%i commands\n", count);
}
