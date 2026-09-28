#include <string.h>

#include "crimsonland_gameplay.h"

highscore_record_t *highscore_find_name_entry(const char *player_name, int count)
{
    int index;

    for (index = 0; index < count; ++index) {
        if (strcmp(player_name, highscore_table[index].player_name) == 0) {
            return &highscore_table[index];
        }
    }
    return 0;
}
