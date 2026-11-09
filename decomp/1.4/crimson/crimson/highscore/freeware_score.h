#ifndef CRIMSON_FREEWARE_SCORE_H
#define CRIMSON_FREEWARE_SCORE_H

#include "cl_build.h"
#include <string.h>

struct freeware_score_entry {
    char name[32];
#if CL_BUILD == 10002
    int value;
#else
    int seconds, value;
    float min_fps, average_fps, max_fps, version;
#endif
};

extern "C" freeware_score_entry freeware_score_table[100];

static __forceinline void freeware_sort_score_table()
{
    // The screen ranks only the name and display value, leaving the other fields in place.
    for (int i = 0; i < 100; ++i) {
        for (int j = 0; j < 100; ++j) {
            if (i != j && freeware_score_table[j].value < freeware_score_table[i].value) {
                int value = freeware_score_table[j].value;
                char name[32];
                strcpy(name, freeware_score_table[j].name);
                strcpy(freeware_score_table[j].name, freeware_score_table[i].name);
                strcpy(freeware_score_table[i].name, name);
                freeware_score_table[j].value = freeware_score_table[i].value;
                freeware_score_table[i].value = value;
            }
        }
    }
}

#endif
