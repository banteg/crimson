#include "crimsonland_gameplay.h"

extern "C" int frame_dt_ms;
extern "C" int quest_spawn_timeline;
extern "C" int quest_spawn_stall_timer_ms;
extern "C" void *creature_spawn_template(int template_id, float *pos, float heading);

extern "C" void quest_spawn_timeline_update(void)
{
    unsigned char creatures_none_active = creatures_any_active_flag;
    if (creatures_none_active) {
        quest_spawn_stall_timer_ms += frame_dt_ms;
    } else {
        quest_spawn_stall_timer_ms = 0;
    }

    int entry_count = quest_spawn_count;
    int entry_index = 0;
    if (entry_count <= 0) {
        return;
    }

    int timeline = quest_spawn_timeline;
    int *trigger_cursor =
        &quest_spawn_table[0].pos_y_block.heading_block.trigger_time_ms;
    while (entry_index < entry_count) {
        if (trigger_cursor[1] > 0) {
            if (trigger_cursor[0] < timeline) {
                goto spawn_entries;
            }
            if (creatures_none_active
                && quest_spawn_stall_timer_ms > 3000
                && timeline > 0x6a4) {
                goto spawn_entries;
            }
        }
        ++entry_index;
        trigger_cursor += sizeof(quest_spawn_entry_t) / sizeof(int);
    }
    return;

spawn_entries:
    vec2f_t zero_offset = {0.0f, 0.0f};
    quest_spawn_entry_t *entry = &quest_spawn_table[entry_index];
    do {
        vec2f_t offset = zero_offset;
        int spawn_index = 0;
        if (entry->pos_y_block.heading_block.count > 0) {
            int *template_id;
            int spread;

            template_id = &entry->pos_y_block.heading_block.template_id;
            spread = 0;
            do {
                if (entry->pos_x < 0.0f
                    || (float)terrain_texture_width < entry->pos_x) {
                    offset.y = (float)spread;
                    if (spawn_index & 1) {
                        offset.y = -offset.y;
                    }
                } else {
                    offset.x = (float)spread;
                    if (spawn_index & 1) {
                        offset.x = -offset.x;
                    }
                }

                float pos[2];
                pos[0] = offset.x + entry->pos_x;
                pos[1] = offset.y + entry->pos_y_block.pos_y;
                creature_spawn_template(
                    *template_id,
                    pos,
                    *(float *)(template_id - 1));

                ++spawn_index;
                spread += 0x28;
            } while (spawn_index < entry->pos_y_block.heading_block.count);
        }

        entry_count = quest_spawn_count;
        entry->pos_y_block.heading_block.count = 0;
        creatures_any_active_flag = 0;
        if (entry_index >= entry_count - 1) {
            return;
        }
        if (entry->pos_y_block.heading_block.trigger_time_ms
            != entry[1].pos_y_block.heading_block.trigger_time_ms) {
            return;
        }
        ++entry_index;
        ++entry;
    } while (true);
}
