#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" char typo_target_name_table[384][64];

extern "C" int typo_target_find_by_name(char *name)
{
    for (int creature_id = 0; creature_id < 384; ++creature_id) {
        if (creature_pool[creature_id].active
            && strcmp(typo_target_name_table[creature_id], name) == 0) {
            return creature_id;
        }
    }
    return -1;
}
