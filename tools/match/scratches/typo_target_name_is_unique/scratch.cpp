#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" char typo_target_name_table[384][64];

extern "C" unsigned char typo_target_name_is_unique(char *name, int creature_id)
{
    for (int index = 0; index < 384; ++index) {
        if (creature_pool[index].active
            && index != creature_id
            && strcmp(typo_target_name_table[index], name) == 0) {
            return 0;
        }
    }
    return 1;
}
