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
};

extern "C" void quest_build_nesting_grounds(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos.x = (float)(terrain_texture_width / 2);
    spawns[0].pos.y = (float)(terrain_texture_height + 64);
    spawns[0].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
    spawns[0].trigger_time_ms = 1500;
    spawns[0].count = config_blob.player_count * 2 + 6;

    spawns[1].pos.x = 256.0f;
    spawns[1].pos.y = 256.0f;
    spawns[1].template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09;
    spawns[1].trigger_time_ms = 8000;
    spawns[1].count = 1;

    spawns[2].pos.x = 512.0f;
    spawns[2].pos.y = 512.0f;
    spawns[2].template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09;
    spawns[2].trigger_time_ms = 13000;
    spawns[2].count = 1;

    spawns[3].pos.x = 768.0f;
    spawns[3].pos.y = 768.0f;
    spawns[3].template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09;
    spawns[3].trigger_time_ms = 18000;
    spawns[3].count = 1;

    spawns[4].pos.x = (float)(terrain_texture_width / 2);
    spawns[4].pos.y = (float)(terrain_texture_height + 64);
    spawns[4].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
    spawns[4].trigger_time_ms = 25000;
    spawns[4].count = config_blob.player_count * 2 + 6;

    spawns[5].pos.x = (float)(terrain_texture_width / 2);
    spawns[5].pos.y = (float)(terrain_texture_height + 64);
    spawns[5].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
    spawns[5].trigger_time_ms = 39000;
    spawns[5].count = config_blob.player_count * 3 + 3;

    spawns[6].pos.x = 384.0f;
    spawns[6].pos.y = 512.0f;
    spawns[6].template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09;
    spawns[6].trigger_time_ms = 41100;
    spawns[6].count = 1;

    spawns[7].pos.x = 640.0f;
    spawns[7].pos.y = 512.0f;
    spawns[7].template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09;
    spawns[7].trigger_time_ms = 42100;
    spawns[7].count = 1;

    spawns[8].pos.x = 512.0f;
    spawns[8].pos.y = 640.0f;
    spawns[8].template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09;
    spawns[8].trigger_time_ms = 43100;
    spawns[8].count = 1;

    spawns[9].pos.x = 512.0f;
    spawns[9].pos.y = 512.0f;
    spawns[9].template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_SLOW_08;
    spawns[9].trigger_time_ms = 44100;
    spawns[9].count = 1;

    spawns[10].pos.x = (float)(terrain_texture_width / 2);
    spawns[10].pos.y = (float)(terrain_texture_height + 64);
    spawns[10].template_id = SPAWN_ID_ALIEN_RANDOM_1E;
    spawns[10].trigger_time_ms = 50000;
    spawns[10].count = config_blob.player_count * 2 + 5;

    spawns[11].pos.x = (float)(terrain_texture_width / 2);
    spawns[11].pos.y = (float)(terrain_texture_height + 64);
    spawns[11].template_id = SPAWN_ID_ALIEN_RANDOM_1F;
    spawns[11].trigger_time_ms = 55000;
    spawns[11].count = config_blob.player_count * 2 + 2;

    *count = 12;
}
