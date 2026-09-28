#include "crimsonland_gameplay.h"

char *format_ordinal(int value)
{
    if (value < 8 || value > 20) {
        int remainder = value % 10;

        if (remainder != 0) {
            if (remainder == 1) {
                crt_sprintf(format_ordinal_buffer, "%d%s", value, "st");
                return format_ordinal_buffer;
            }
            if (remainder == 2) {
                crt_sprintf(format_ordinal_buffer, "%d%s", value, "nd");
                return format_ordinal_buffer;
            }
            if (remainder == 3) {
                crt_sprintf(format_ordinal_buffer, "%d%s", value, "rd");
                return format_ordinal_buffer;
            }
        }
    }

    crt_sprintf(format_ordinal_buffer, "%d%s", value, "th");
    return format_ordinal_buffer;
}
