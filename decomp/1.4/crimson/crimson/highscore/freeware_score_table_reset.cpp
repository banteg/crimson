#include "freeware_score.h"
#include <stdio.h>
#include <string.h>

extern "C" void freeware_score_table_reset()
{
    for (int i = 0; i < 100; ++i) {
        freeware_score_entry &entry = freeware_score_table[i];
#if CL_BUILD >= 10400
        memset(&entry, 0, sizeof(entry));
#else
        entry.value = 0;
#endif
        sprintf(entry.name, "10tons");
    }
}
