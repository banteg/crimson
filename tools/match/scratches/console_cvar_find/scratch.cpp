#include <string.h>

#include "crimsonland_console.h"

console_cvar_entry_t *console_queue_t::console_cvar_find(char *name)
{
    console_cvar_entry_t *entry = cvar_head;

    while (entry) {
        if (strcmp(name, entry->name) == 0) {
            return entry;
        }

        entry = entry->next;
    }

    return 0;
}
