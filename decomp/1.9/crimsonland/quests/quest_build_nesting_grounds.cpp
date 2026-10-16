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
    int entry_count = 0;

    spawns[entry_count].pos.x = (float)(terrain_texture_width / 2);
    spawns[entry_count].pos.y = (float)(terrain_texture_height + 64);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
    spawns[entry_count].trigger_time_ms = 1500;
    spawns[entry_count].count = config_blob.player_count * 2 + 6;
    ++entry_count;

    spawns[entry_count].pos.x = 256.0f;
    spawns[entry_count].pos.y = 256.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09;
    spawns[entry_count].trigger_time_ms = 8000;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.x = 512.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09;
    spawns[entry_count].trigger_time_ms = 13000;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.x = 768.0f;
    spawns[entry_count].pos.y = 768.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09;
    spawns[entry_count].trigger_time_ms = 18000;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.x = (float)(terrain_texture_width / 2);
    spawns[entry_count].pos.y = (float)(terrain_texture_height + 64);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
    spawns[entry_count].trigger_time_ms = 25000;
    spawns[entry_count].count = config_blob.player_count * 2 + 6;
    ++entry_count;

    spawns[entry_count].pos.x = (float)(terrain_texture_width / 2);
    spawns[entry_count].pos.y = (float)(terrain_texture_height + 64);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
    spawns[entry_count].trigger_time_ms = 39000;
    spawns[entry_count].count = config_blob.player_count * 3 + 3;
    ++entry_count;

    spawns[entry_count].pos.x = 384.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09;
    spawns[entry_count].trigger_time_ms = 41100;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.x = 640.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09;
    spawns[entry_count].trigger_time_ms = 42100;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.x = 512.0f;
    spawns[entry_count].pos.y = 640.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09;
    spawns[entry_count].trigger_time_ms = 43100;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.x = 512.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_BASIC_SLOWER_08;
    spawns[entry_count].trigger_time_ms = 44100;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.x = (float)(terrain_texture_width / 2);
    spawns[entry_count].pos.y = (float)(terrain_texture_height + 64);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_RANDOM_1E;
    spawns[entry_count].trigger_time_ms = 50000;
    spawns[entry_count].count = config_blob.player_count * 2 + 5;
    ++entry_count;

    spawns[entry_count].pos.x = (float)(terrain_texture_width / 2);
    spawns[entry_count].pos.y = (float)(terrain_texture_height + 64);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_RANDOM_1F;
    spawns[entry_count].trigger_time_ms = 55000;
    spawns[entry_count].count = config_blob.player_count * 2 + 2;
    ++entry_count;

    *count = entry_count;
}
