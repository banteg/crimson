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

    void set_template(int spawn_template_id)
    {
        template_id = spawn_template_id;
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
        int template_id = (entry_count & 1)
            ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
            : SPAWN_ID_DEN_ALIEN_BASIC_07;
        ++entry_count;
        spawn->set_template(template_id);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
        offset += 0x270;
        trigger_time_ms += 1800;
        ++spawn;
    }

    offset = 0;
    int toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = (float)(0x338 - offset / 10);
        spawn->pos.y = 824.0f;
        spawn->set_template(
            (toggle & 1)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
        offset += 0x270;
        trigger_time_ms += 1500;
        ++toggle;
        ++spawn;
    }

    spawn = &spawns[entry_count];
    spawn->pos.x = 512.0f;
    spawn->pos.y = 512.0f;
    spawn->trigger_time_ms = trigger_time_ms;
    spawn->set_template(SPAWN_ID_DEN_ALIEN_BASIC_07);
    spawn->count = 1;
    ++entry_count;

    offset = 0;
    toggle = 0;
    spawn = &spawns[entry_count];
    entry_count += 10;
    while (offset < 0x1860) {
        spawn->pos.x = 200.0f;
        spawn->pos.y = (float)(0x338 - offset / 10);
        spawn->set_template(
            (toggle & 1)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
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
        spawn->set_template(
            (toggle & 1)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
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
        spawn->set_template(
            (toggle & 1)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
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
        spawn->set_template(
            (toggle & 1)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
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
        spawn->set_template(
            (toggle & 1)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
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
        spawn->set_template(
            (toggle & 1)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
        offset += 0x270;
        trigger_time_ms += 800;
        ++toggle;
        ++spawn;
    }

    *count = entry_count;
}
