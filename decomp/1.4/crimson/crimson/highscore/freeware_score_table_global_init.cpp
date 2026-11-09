#include "freeware_score.h"
#include <stdio.h>

extern "C" void freeware_score_table_global_init()
{
    freeware_score_entry *entry = freeware_score_table;
    int remaining = 100;
    do {
#if CL_BUILD == 10400
        entry->seconds = 0;
#endif
#if CL_BUILD > 10002
        entry->average_fps = 1;
        entry->min_fps = 1;
#if CL_BUILD == 10400
        entry->version = 1.4f;
#else
        entry->version = 1.3f;
#endif
#endif
        entry->value = 0;
        sprintf(entry->name, "10tons");
        ++entry;
    } while (--remaining);
}
