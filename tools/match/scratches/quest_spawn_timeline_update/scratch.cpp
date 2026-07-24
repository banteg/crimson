#include "crimsonland_gameplay.h"

struct quest_timeline_vec2_t {
    float x;
    float y;

    quest_timeline_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    quest_timeline_vec2_t operator+(const quest_timeline_vec2_t &other) const
    {
        return quest_timeline_vec2_t(x + other.x, y + other.y);
    }
};

struct quest_timeline_entry_t {
    quest_timeline_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;
};

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
    quest_timeline_vec2_t zero_offset(0.0f, 0.0f);
    quest_timeline_entry_t *entry =
        (quest_timeline_entry_t *)&quest_spawn_table[entry_index];
    do {
        quest_timeline_vec2_t offset = zero_offset;
        int spawn_index = 0;
        if (entry->count > 0) {
            int *template_id = &entry->template_id;
            int spread;

            spread = 0;
            do {
                if (entry->pos.x < 0.0f
                    || (float)terrain_texture_width < entry->pos.x) {
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

                quest_timeline_vec2_t pos = offset + entry->pos;
                creature_spawn_template(
                    *template_id,
                    &pos.x,
                    entry->heading);

                ++spawn_index;
                spread += 0x28;
            } while (spawn_index < entry->count);
        }

        entry_count = quest_spawn_count;
        entry->count = 0;
        creatures_any_active_flag = 0;
        if (entry_index >= entry_count - 1) {
            return;
        }
        if (entry->trigger_time_ms != entry[1].trigger_time_ms) {
            return;
        }
        ++entry_index;
        ++entry;
    } while (true);
}
