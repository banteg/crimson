#include "crimsonland_gameplay.h"

char *time_format_mm_ss(int total_seconds)
{
    int seconds = total_seconds % 60;

    if (seconds < 10) {
        crt_sprintf(time_format_mm_ss_buffer, "%d:0%d", total_seconds / 60, seconds);
    } else {
        crt_sprintf(time_format_mm_ss_buffer, "%d:%d", total_seconds / 60, seconds);
    }
    return time_format_mm_ss_buffer;
}
