#include "crimsonland_console.h"

extern "C" void crt_free(void *ptr);

inline console_log_node_t::console_log_node_t(void)
{
    next = 0;
    text = 0;
}

inline console_log_node_t::~console_log_node_t(void)
{
    if (text != 0) {
        crt_free(text);
    }
    text = 0;
    if (next != 0) {
        next->release(1);
    }
    next = 0;
}

void console_queue_t::console_push_line(char *line)
{
    if (echo_enabled != 0) {
        if (log_count == 4096) {
            console_log_node_t *entry = log_head;
            while (entry->next->next != 0) {
                entry = entry->next;
            }
            delete entry->next;
            entry->next = 0;
            --log_count;
        }

        console_log_node_t *entry = new console_log_node_t;
        entry->text = strdup_malloc(line);
        entry->next = log_head;
        log_head = entry;
        ++log_count;
    }
}
