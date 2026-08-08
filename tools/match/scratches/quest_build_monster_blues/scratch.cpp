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

    void set_spawn(
        int spawn_template_id,
        int spawn_trigger_time_ms,
        int spawn_count)
    {
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
        count = spawn_count;
    }
};

extern "C" void quest_build_monster_blues(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(
        -50.0f,
        (float)terrain_texture_height * 0.5f);
    spawns[entry_count].set_spawn(SPAWN_ID_LIZARD_RANDOM_04, 500, 10);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(
        1074.0f,
        (float)terrain_texture_height * 0.5f);
    spawns[entry_count].set_spawn(SPAWN_ID_ALIEN_RANDOM_06, 7500, 10);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(512.0f, 1088.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_SPIDER_SP1_RANDOM_03, 17500, 12);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(512.0f, -64.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_SPIDER_SP1_RANDOM_03, 17500, 12);
    ++entry_count;

    int trigger_time_ms = 27500;
    int index = 0;
    do {
        quest_entry_original_t *spawn = &spawns[index + 4];
        spawn->pos = quest_vec2_t(-64.0f, 512.0f);

        if (index % 4 == 0) {
            spawn->template_id = SPAWN_ID_ALIEN_RANDOM_06;
        } else if (index % 4 == 1) {
            spawn->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_03;
        } else {
            spawn->template_id = SPAWN_ID_SPIDER_SP2_RANDOM_05;
        }

        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = index / 8 + 2;

        trigger_time_ms += 900;
        ++index;
    } while (index < 0x40);

    *count = 0x44;
}
