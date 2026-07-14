#include "crimsonland_gameplay.h"

unsigned char quest_spawn_table_empty(void)
{
    int index;

    for (index = quest_spawn_count - 1; index >= 0; --index) {
        if (quest_spawn_table[index].pos_y_block.heading_block.count > 0) {
            return 0;
        }
    }
    return 1;
}
