#include <string.h>

#include "crimsonland_console.h"

char *console_queue_t::console_cvar_autocomplete(char *prefix)
{
    unsigned int length = strlen(prefix);
    if (!length) {
        return 0;
    }

    console_cvar_entry_t *entry = cvar_head;
    while (entry) {
        if (strcmp(prefix, entry->name) == 0) {
            return entry->name;
        }
        entry = entry->next;
    }

    entry = cvar_head;
    while (entry) {
        if (strncmp(prefix, entry->name, length) == 0) {
            return entry->name;
        }
        entry = entry->next;
    }
    return 0;
}
