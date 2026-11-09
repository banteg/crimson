#include "freeware_score.h"

extern "C" void freeware_score_table_global_init()
{
    freeware_score_entry *entry = freeware_score_table;
    int remaining = 100;
    do {
        freeware_initialize_score_entry(*entry);
        ++entry;
    } while (--remaining);
}
