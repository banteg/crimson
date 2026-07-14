#include "crimsonland_gameplay.h"

extern "C" void credits_line_set(int index, char *text, int flags)
{
    credits_line_table[index].flags = flags;
    if (credits_line_table[index].text != 0) {
        crt_free(credits_line_table[index].text);
    }
    credits_line_table[index].text = strdup_malloc(text);
    credits_line_max_index = index;
}
