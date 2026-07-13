#include "crimsonland_gameplay.h"

void effect_free(effect_entry_t *entry)
{
    entry->next_free = effect_free_list_head;
    entry->flags = 0;
    effect_free_list_head = entry;
}
