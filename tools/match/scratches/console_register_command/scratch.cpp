#include "crimsonland_console.h"

void console_queue_t::console_register_command(
    char *name, void (*handler)(void))
{
    console_command_entry_t *entry = new console_command_entry_t(name);
    entry->handler = handler;

    if (!command_head) {
        command_head = entry;
        return;
    }

    console_command_entry_t *cursor = command_head;
    while (cursor->next) {
        cursor = cursor->next;
    }
    cursor->next = entry;
}
