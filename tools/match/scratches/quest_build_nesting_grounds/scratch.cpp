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

    void set_spawn(int spawn_template_id, int spawn_trigger_time_ms) {
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
    }
};

extern "C" void quest_build_nesting_grounds(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos.x = (float)(terrain_texture_width / 2);
    spawns[0].pos.y = (float)(terrain_texture_height + 64);
    spawns[0].set_spawn(SPAWN_ID_ALIEN_RANDOM_1D, 1500);
    spawns[0].count = config_blob.player_count * 2 + 6;

    spawns[1].pos.x = 256.0f;
    spawns[1].pos.y = 256.0f;
    spawns[1].set_spawn(
        SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09,
        8000);
    spawns[1].count = 1;

    spawns[2].pos.x = 512.0f;
    spawns[2].pos.y = 512.0f;
    spawns[2].set_spawn(
        SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09,
        13000);
    spawns[2].count = 1;

    spawns[3].pos.x = 768.0f;
    spawns[3].pos.y = 768.0f;
    spawns[3].set_spawn(
        SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09,
        18000);
    spawns[3].count = 1;

    spawns[4].pos.x = (float)(terrain_texture_width / 2);
    spawns[4].pos.y = (float)(terrain_texture_height + 64);
    spawns[4].set_spawn(SPAWN_ID_ALIEN_RANDOM_1D, 25000);
    spawns[4].count = config_blob.player_count * 2 + 6;

    spawns[5].pos.x = (float)(terrain_texture_width / 2);
    spawns[5].pos.y = (float)(terrain_texture_height + 64);
    spawns[5].set_spawn(SPAWN_ID_ALIEN_RANDOM_1D, 39000);
    spawns[5].count = config_blob.player_count * 3 + 3;

    quest_vec2_t *entry_six_pos = &spawns[6].pos;
    entry_six_pos->x = 384.0f;
    entry_six_pos->y = 512.0f;
    spawns[6].set_spawn(
        SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09,
        41100);
    spawns[6].count = 1;

    spawns[7].pos.x = 640.0f;
    spawns[7].pos.y = 512.0f;
    spawns[7].set_spawn(
        SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09,
        42100);
    spawns[7].count = 1;

    spawns[8].pos.x = 512.0f;
    spawns[8].pos.y = 640.0f;
    spawns[8].set_spawn(
        SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09,
        43100);
    spawns[8].count = 1;

    spawns[9].pos.x = 512.0f;
    spawns[9].pos.y = 512.0f;
    spawns[9].set_spawn(
        SPAWN_ID_DEN_ALIEN_BASIC_SLOWER_08,
        44100);
    spawns[9].count = 1;

    spawns[10].pos.x = (float)(terrain_texture_width / 2);
    spawns[10].pos.y = (float)(terrain_texture_height + 64);
    spawns[10].set_spawn(SPAWN_ID_ALIEN_RANDOM_1E, 50000);
    spawns[10].count = config_blob.player_count * 2 + 5;

    spawns[11].pos.x = (float)(terrain_texture_width / 2);
    spawns[11].pos.y = (float)(terrain_texture_height + 64);
    spawns[11].set_spawn(SPAWN_ID_ALIEN_RANDOM_1F, 55000);
    spawns[11].count = config_blob.player_count * 2 + 2;

    *count = 12;
}
