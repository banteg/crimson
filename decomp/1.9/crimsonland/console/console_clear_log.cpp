#include "crimsonland_console.h"

extern "C" void crt_free(void *ptr);

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

extern "C" void console_clear_log(void)
{
    delete console_log_queue.log_head;
    console_log_queue.log_head = 0;
    console_log_queue.log_count = 0;
    console_log_queue.scroll_offset = 0;
}
