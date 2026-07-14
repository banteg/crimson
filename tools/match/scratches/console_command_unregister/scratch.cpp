#include "crimsonland_console.h"

unsigned char console_queue_t::console_command_unregister(char *name)
{
    console_command_entry_t *entry = console_command_find(name);
    if (!entry) {
        return 0;
    }

    console_command_entry_t *cursor = command_head;
    if (entry == cursor) {
        command_head = cursor->next;
        return 1;
    }

    while (cursor) {
        if (cursor->next == entry) {
            cursor->next = cursor->next->next;
            return 1;
        }
        cursor = cursor->next;
    }
    return 0;
}
