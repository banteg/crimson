#include "crimsonland_console.h"

extern console_queue_t console_log_queue;

extern "C" void console_global_destroy(void)
{
    console_log_queue.~console_queue_t();
}
