#include <stdarg.h>

#include "crimsonland_console.h"

extern "C" void console_printf(
    console_queue_t *queue,
    char *format,
    ...)
{
    if (queue->echo_enabled != 0) {
        va_list args;

        va_start(args, format);
        crt_vsprintf(console_format_buffer, format, args);
        va_end(args);
        queue->console_push_line(console_format_buffer);
    }
}
