#include <new.h>

#include "crimsonland_console.h"

extern console_queue_t console_log_queue;

extern "C" void console_global_init(void)
{
    console_queue_t *queue = &console_log_queue;
    __assume(queue != 0);
    new (queue) console_queue_t;
}
