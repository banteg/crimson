#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"

struct quest_timeline_vec2_t : vec2f_t {
    quest_timeline_vec2_t(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }

    quest_timeline_vec2_t operator+(const vec2f_t &other) const
    {
        return quest_timeline_vec2_t(x + other.x, y + other.y);
    }
};

extern "C" int frame_dt_ms;
extern "C" int quest_spawn_timeline;
extern "C" int quest_spawn_stall_timer_ms;

extern "C" void quest_spawn_timeline_update(void)
{
    int entry_index;
    int spawn_index;
    unsigned char creatures_none_active = creatures_none_active_flag;

    if (creatures_none_active) {
        quest_spawn_stall_timer_ms += frame_dt_ms;
    } else {
        quest_spawn_stall_timer_ms = 0;
    }

    for (entry_index = 0; entry_index < quest_spawn_count; entry_index++) {
        if (quest_spawn_table[entry_index].count > 0
            && (quest_spawn_table[entry_index].trigger_time_ms < quest_spawn_timeline
                || (creatures_none_active
                    && quest_spawn_stall_timer_ms > 3000
                    && quest_spawn_timeline > 0x6a4))) {
            goto spawn_entries;
        }
    }
    return;

spawn_entries:
    quest_timeline_vec2_t zero_offset(0.0f, 0.0f);
    spawn_index = 0;
    while (true) {
        quest_timeline_vec2_t offset = zero_offset;
        for (; spawn_index < quest_spawn_table[entry_index].count; spawn_index++) {
            if (quest_spawn_table[entry_index].position.x < 0.0f
                || (float)terrain_texture_width < quest_spawn_table[entry_index].position.x) {
                offset.y = (float)(spawn_index * 40);
                if (spawn_index & 1) {
                    offset.y = -offset.y;
                }
            } else {
                offset.x = (float)(spawn_index * 40);
                if (spawn_index & 1) {
                    offset.x = -offset.x;
                }
            }

            quest_timeline_vec2_t pos = offset + quest_spawn_table[entry_index].position;
            creature_spawn_template(
                quest_spawn_table[entry_index].template_id,
                &pos,
                quest_spawn_table[entry_index].heading);
        }

        quest_spawn_table[entry_index].count = 0;
        creatures_none_active_flag = 0;
        if (entry_index >= quest_spawn_count - 1) {
            return;
        }
        if (quest_spawn_table[entry_index].trigger_time_ms
            != quest_spawn_table[entry_index + 1].trigger_time_ms) {
            return;
        }
        entry_index++;
        spawn_index = 0;
    }
}
