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

extern "C" void quest_build_the_beating(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos = quest_vec2_t(256.0f, 256.0f);
    spawns[0].set_spawn(
        SPAWN_ID_ALIEN_BONUS_CARRIER_27,
        500,
        1);

    spawns[1].pos = quest_vec2_t(
        (float)(terrain_texture_width + 32),
        (float)(terrain_texture_height / 2));
    spawns[1].set_spawn(
        SPAWN_ID_ALIEN_BIG_GRAY_29,
        8000,
        3);

    int trigger_time_ms = 10000;
    int x_offset = 64;
    int remaining = 8;
    quest_entry_original_t *spawn = &spawns[2];
    do {
        spawn->pos = quest_vec2_t(
            (float)(terrain_texture_width + x_offset),
            (float)(terrain_texture_height / 2));
        x_offset += 32;
        ++spawn;
        spawn[-1].template_id = SPAWN_ID_ALIEN_SMALL_GREEN_MAN_25;
        spawn[-1].trigger_time_ms = trigger_time_ms;
        spawn[-1].count = 8;
        trigger_time_ms += 100;
        --remaining;
    } while (remaining != 0);

    spawns[10].pos = quest_vec2_t(
        -32.0f,
        (float)(terrain_texture_height / 2));
    spawns[10].set_spawn(
        SPAWN_ID_ALIEN_BIG_GRAY_29,
        18000,
        3);

    int x = -64;
    trigger_time_ms = 20000;
    spawn = &spawns[11];
    do {
        spawn->pos = quest_vec2_t(
            (float)x,
            (float)(terrain_texture_height / 2));
        ++spawn;
        spawn[-1].template_id = SPAWN_ID_ALIEN_SMALL_GREEN_MAN_25;
        spawn[-1].trigger_time_ms = trigger_time_ms;
        spawn[-1].count = 8;
        trigger_time_ms += 100;
        x -= 32;
    } while (x > -320);

    int y = -64;
    trigger_time_ms = 40000;
    spawn = &spawns[19];
    do {
        spawn->pos = quest_vec2_t(
            (float)(terrain_texture_width / 2),
            (float)y);
        ++spawn;
        spawn[-1].template_id = SPAWN_ID_ALIEN_GHOST_0F;
        spawn[-1].trigger_time_ms = trigger_time_ms;
        spawn[-1].count = 4;
        trigger_time_ms += 100;
        y -= 42;
    } while (y > -316);

    int y_offset = 0;
    trigger_time_ms = 40000;
    spawn = &spawns[25];
    do {
        spawn->pos = quest_vec2_t(
            (float)(terrain_texture_width / 2),
            (float)(terrain_texture_width + y_offset + 44));
        ++spawn;
        spawn[-1].template_id = SPAWN_ID_FORMATION_RING_ALIEN_8_12;
        spawn[-1].trigger_time_ms = trigger_time_ms;
        spawn[-1].count = 2;
        y_offset += 32;
        trigger_time_ms += 100;
    } while (trigger_time_ms < 40600);

    *count = 31;
}
