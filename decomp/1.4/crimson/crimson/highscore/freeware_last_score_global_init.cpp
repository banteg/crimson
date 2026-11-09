#include "freeware_score.h"

extern "C" freeware_score_entry freeware_last_score;

extern "C" void freeware_last_score_global_init()
{
    freeware_initialize_score_entry(freeware_last_score);
}
