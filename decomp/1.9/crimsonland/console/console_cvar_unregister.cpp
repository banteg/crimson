#include "crimsonland_console.h"

unsigned char console_queue_t::console_cvar_unregister(char *name)
{
    console_cvar_entry_t *entry = console_cvar_find(name);
    if (!entry) {
        return 0;
    }

    console_cvar_entry_t *cursor = cvar_head;
    if (entry == cursor) {
        cvar_head = cursor->next;
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
