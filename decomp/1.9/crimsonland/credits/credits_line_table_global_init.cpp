#include "crimsonland_gameplay.h"

extern "C" void credits_line_table_global_init(void)
{
    int remaining = 0x100;
    credits_line_t *line = credits_line_table;

    do {
        line->flags = 0;
        line->text = 0;
        ++line;
    } while (--remaining != 0);
}
