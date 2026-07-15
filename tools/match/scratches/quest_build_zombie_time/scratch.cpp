#include "crimsonland_gameplay.h"

extern "C" void quest_build_zombie_time(quest_spawn_entry_t *entries, int *count)
{
    int entry_index = 0;
    for (int trigger_time = 1500; trigger_time < 97500; trigger_time += 8000) {
        quest_spawn_entry_t *right = &entries[entry_index++];
        right->pos_x = (float)(terrain_texture_width + 64);
        right->pos_y_block.pos_y = (float)(terrain_texture_width / 2);
        right->pos_y_block.heading_block.template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        right->pos_y_block.heading_block.trigger_time_ms = trigger_time;
        right->pos_y_block.heading_block.count = 8;
        quest_spawn_entry_t *left = &entries[entry_index++];
        left->pos_x = -64.0f;
        left->pos_y_block.pos_y = (float)(terrain_texture_width / 2);
        left->pos_y_block.heading_block.template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        left->pos_y_block.heading_block.trigger_time_ms = trigger_time;
        left->pos_y_block.heading_block.count = 8;
    }

    *count = entry_index;
}
