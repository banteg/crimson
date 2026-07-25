#include <math.h>

#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;
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

extern "C" void quest_build_gauntlet(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    if (config_hardcore != 0) {
        config_blob.player_count += 4;
    }

    if (config_blob.player_count + 9 > 0) {
        int trigger_time_ms = 0;
        do {
            quest_entry_original_t *spawn = &spawns[entry_count];
            spawn->pos.x =
                (float)cos(
                    (float)entry_count * 6.28318548f /
                    (float)(config_blob.player_count + 9)) *
                    158.0f +
                512.0f;
            spawn->pos.y =
                (float)sin(
                    (float)entry_count * 6.28318548f /
                    (float)(config_blob.player_count + 9)) *
                    158.0f +
                512.0f;
            spawn->template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            spawn->trigger_time_ms = trigger_time_ms;
            spawn->count = 1;
            ++entry_count;
            trigger_time_ms += 200;
        } while (entry_count < config_blob.player_count + 9);
    }

    if (config_blob.player_count + 9 > 0) {
        int spawn_count = 2;
        int trigger_time_ms = 4000;
        do {
            quest_entry_original_t *spawn = &spawns[entry_count];
            spawn->pos.x = (float)(terrain_texture_width + 64);
            spawn->pos.y = (float)(terrain_texture_width / 2);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms,
                spawn_count);
            ++entry_count;

            spawn = &spawns[entry_count];
            spawn->pos.x = -64.0f;
            spawn->pos.y = (float)(terrain_texture_width / 2);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms,
                spawn_count);
            ++entry_count;

            spawn = &spawns[entry_count];
            spawn->pos.x = (float)(terrain_texture_width / 2);
            spawn->pos.y = (float)(terrain_texture_width + 64);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms,
                spawn_count);
            ++entry_count;

            spawn = &spawns[entry_count];
            spawn->pos.x = (float)(terrain_texture_width / 2);
            spawn->pos.y = -64.0f;
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms,
                spawn_count);
            ++entry_count;

            trigger_time_ms += 5500;
            ++spawn_count;
        } while (spawn_count - 2 < config_blob.player_count + 9);
    }

    int ring_index = 0;
    int outer_count = config_blob.player_count + 17;
    if (outer_count > 0) {
        int trigger_time_ms = 42500;
        do {
            quest_entry_original_t *spawn = &spawns[entry_count];
            spawn->pos.x =
                (float)cos(
                    (float)ring_index * 6.28318548f /
                    (float)(config_blob.player_count + 17)) *
                    258.0f +
                512.0f;
            spawn->pos.y =
                (float)sin(
                    (float)ring_index * 6.28318548f /
                    (float)(config_blob.player_count + 17)) *
                    258.0f +
                512.0f;
            spawn->template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            spawn->trigger_time_ms = trigger_time_ms;
            spawn->count = 1;
            ++entry_count;
            trigger_time_ms += 500;
            ++ring_index;
        } while (ring_index < config_blob.player_count + 17);
    }

    if (config_hardcore != 0) {
        config_blob.player_count -= 4;
    }

    *count = entry_count;
}
