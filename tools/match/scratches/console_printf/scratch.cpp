#include <stdarg.h>

#include "crimsonland_console.h"

extern "C" unsigned char console_printf(
    console_queue_t *queue,
    char *format,
    ...)
{
    unsigned char result = queue->echo_enabled;

    if (result) {
        va_list args;

        va_start(args, format);
        crt_vsprintf(console_format_buffer, format, args);
        va_end(args);
        result = queue->console_push_line(console_format_buffer);
    }

    return result;
}
