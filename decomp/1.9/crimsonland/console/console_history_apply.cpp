#include <string.h>

#include "crimsonland_console.h"

extern "C" char console_input_buf[1024];
extern "C" int console_input_cursor;
extern "C" unsigned char console_input_ready;

void console_queue_t::console_history_apply(void)
{
    console_history_entry_t *entry = history_head;
    int index = 0;

    for (; index < history_index - 1; ++index) {
        console_history_entry_t *next = entry->next;
        if (!next) {
            history_index = index;
            break;
        }
        entry = next;
    }

    strcpy(console_input_buf, entry->line);
    console_input_cursor = strlen(console_input_buf);
    console_input_ready = 0;
}
