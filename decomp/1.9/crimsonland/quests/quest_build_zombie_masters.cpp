#include "crimsonland_gameplay.h"

inline void set_position(
    quest_spawn_entry_t *entry, float x_value, float y_value)
{
    entry->pos_x = x_value;
    entry->pos_y = y_value;
}

inline void set_spawn(
    quest_spawn_entry_t *entry,
    int spawn_template_id,
    int spawn_trigger_time_ms)
{
    entry->template_id = spawn_template_id;
    entry->trigger_time_ms = spawn_trigger_time_ms;
}

extern "C" void quest_build_zombie_masters(
    quest_spawn_entry_t *entries, int *count)
{
    set_position(&entries[0], 256.0f, 256.0f);
    set_spawn(&entries[0], SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 1000);
    entries[0].count = config_blob.player_count;

    set_position(&entries[1], 512.0f, 256.0f);
    set_spawn(&entries[1], SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 6000);
    entries[1].count = 1;

    set_position(&entries[2], 768.0f, 256.0f);
    set_spawn(&entries[2], SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 14000);
    entries[2].count = config_blob.player_count;

    set_position(&entries[3], 768.0f, 768.0f);
    set_spawn(&entries[3], SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 18000);
    entries[3].count = 1;

    *count = 4;
}
