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

extern "C" void quest_build_the_unblitzkrieg(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int trigger_time_ms = 500;
    int entry_count = 0;
    int offset = 0;
    quest_entry_original_t *spawn = spawns;

    while (offset < 0x1860) {
        spawn->pos.x = 824.0f;
        spawn->pos.y = (float)(offset / 10 + 200);
        spawn->set_spawn(
            (entry_count & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 1800;
        ++entry_count;
        ++spawn;
    }

    offset = 0;
    int toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = (float)(0x338 - offset / 10);
        spawn->pos.y = 824.0f;
        spawn->set_spawn(
            (toggle & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 1500;
        ++toggle;
        ++spawn;
    }

    spawn = &spawns[entry_count];
    spawn->pos.x = 512.0f;
    spawn->pos.y = 512.0f;
    spawn->set_spawn(
        SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
        trigger_time_ms,
        1);
    ++entry_count;

    offset = 0;
    toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = 200.0f;
        spawn->pos.y = (float)(0x338 - offset / 10);
        spawn->set_spawn(
            (toggle & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 1200;
        ++toggle;
        ++spawn;
    }

    offset = 0;
    toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = (float)(offset / 10 + 200);
        spawn->pos.y = 200.0f;
        spawn->set_spawn(
            (toggle & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 800;
        ++toggle;
        ++spawn;
    }

    offset = 0;
    toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = 824.0f;
        spawn->pos.y = (float)(offset / 10 + 200);
        spawn->set_spawn(
            (toggle & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 800;
        ++toggle;
        ++spawn;
    }

    offset = 0;
    toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = (float)(0x338 - offset / 10);
        spawn->pos.y = 824.0f;
        spawn->set_spawn(
            (toggle & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 700;
        ++toggle;
        ++spawn;
    }

    offset = 0;
    toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = 200.0f;
        spawn->pos.y = (float)(0x338 - offset / 10);
        spawn->set_spawn(
            (toggle & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 700;
        ++toggle;
        ++spawn;
    }

    offset = 0;
    toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = (float)(offset / 10 + 200);
        spawn->pos.y = 200.0f;
        spawn->set_spawn(
            (toggle & 1)
                ? SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D
                : SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);
        offset += 0x270;
        trigger_time_ms += 800;
        ++toggle;
        ++spawn;
    }

    *count = entry_count;
}
