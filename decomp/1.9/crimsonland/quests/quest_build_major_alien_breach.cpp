#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    quest_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;

    void set(
        const quest_vec2_t &position,
        int spawn_template_id,
        int spawn_trigger_time_ms,
        int spawn_count)
    {
        pos = position;
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
        count = spawn_count;
    }
};

struct quest_spawn_builder_t {
    quest_entry_original_t *cursor;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : cursor(spawn_entries), count(0) {}

    void add(
        const quest_vec2_t &position,
        int spawn_template_id,
        int spawn_trigger_time_ms,
        int spawn_count)
    {
        ++count;
        cursor->pos = position;
        cursor->template_id = spawn_template_id;
        cursor->trigger_time_ms = spawn_trigger_time_ms;
        cursor->count = spawn_count;
        ++cursor;
    }
};

extern "C" void quest_build_major_alien_breach(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int trigger_time_ms = 4000;

    for (int wave = 0; wave < 100; ++wave) {
        builder.add(
            quest_vec2_t(1088.0f, 512.0f),
            SPAWN_ID_ALIEN_RANDOM_GREEN_20,
            trigger_time_ms,
            2);

        builder.add(
            quest_vec2_t(512.0f, -64.0f),
            SPAWN_ID_ALIEN_RANDOM_GREEN_20,
            trigger_time_ms,
            2);

        trigger_time_ms += 2000 - wave * 15;
        if (trigger_time_ms < 1000) {
            trigger_time_ms = 1000;
        }
    }

    *count = builder.count;
}
