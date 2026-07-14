#include <string.h>

#include "crimsonland_console.h"

console_command_entry_t *console_queue_t::console_command_find(char *name)
{
    console_command_entry_t *entry = command_head;

    while (entry) {
        if (strcmp(name, entry->name) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    return 0;
}
