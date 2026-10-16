#include "crimsonland_gameplay.h"

#if CL_BUILD == 10908
// Code generation only: with dword parity tests C2 9044 shares one constant-1
// register between them and the count stores for the whole function, where
// 1.9.8 keeps immediates. No shared spelling was found (see the scratch NOTES).
#define QUEST_PARITY(value) ((unsigned char)(value) & 1)
#else
#define QUEST_PARITY(value) ((value) & 1)
#endif

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
        int template_id = QUEST_PARITY(entry_count)
            ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
            : SPAWN_ID_DEN_ALIEN_BASIC_07;
        ++entry_count;
        spawn->set_template(template_id);
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
        offset += 0x270;
        ++spawn;
        trigger_time_ms += 1800;
    }

    offset = 0;
    int toggle = 0;
    while (offset < 0x1860) {
        spawns[entry_count].pos.x = (float)(0x338 - offset / 10);
        spawns[entry_count].pos.y = 824.0f;
        spawns[entry_count].template_id = QUEST_PARITY(toggle)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count++].count = 1;
        trigger_time_ms += 1500;
        offset += 0x270;
        ++toggle;
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
    while (offset < 0x1860) {
        spawns[entry_count].pos.x = 200.0f;
        spawns[entry_count].pos.y = (float)(0x338 - offset / 10);
        spawns[entry_count].set_template(
            QUEST_PARITY(toggle)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count++].count = 1;
        trigger_time_ms += 1200;
        offset += 0x270;
        ++toggle;
    }

    offset = 0;
    toggle = 0;
    while (offset < 0x1860) {
        spawns[entry_count].pos.x = (float)(offset / 10 + 200);
        spawns[entry_count].pos.y = 200.0f;
        spawns[entry_count].template_id = QUEST_PARITY(toggle)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count++].count = 1;
        trigger_time_ms += 800;
        offset += 0x270;
        ++toggle;
    }

    offset = 0;
    toggle = 0;
    while (offset < 0x1860) {
        spawns[entry_count].pos.x = 824.0f;
        spawns[entry_count].pos.y = (float)(offset / 10 + 200);
        spawns[entry_count].set_template(
            QUEST_PARITY(toggle)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count++].count = 1;
        trigger_time_ms += 800;
        offset += 0x270;
        ++toggle;
    }

    offset = 0;
    toggle = 0;
    while (offset < 0x1860) {
        spawns[entry_count].pos.x = (float)(0x338 - offset / 10);
        spawns[entry_count].pos.y = 824.0f;
        spawns[entry_count].template_id = QUEST_PARITY(toggle)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count++].count = 1;
        trigger_time_ms += 700;
        offset += 0x270;
        ++toggle;
    }

    offset = 0;
    toggle = 0;
    while (offset < 0x1860) {
        spawns[entry_count].pos.x = 200.0f;
        spawns[entry_count].pos.y = (float)(0x338 - offset / 10);
        spawns[entry_count].set_template(
            QUEST_PARITY(toggle)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07);
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count++].count = 1;
        trigger_time_ms += 700;
        offset += 0x270;
        ++toggle;
    }

    offset = 0;
    toggle = 0;
    while (offset < 0x1860) {
        spawns[entry_count].pos.x = (float)(offset / 10 + 200);
        spawns[entry_count].pos.y = 200.0f;
        spawns[entry_count].template_id = QUEST_PARITY(toggle)
                ? SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D
                : SPAWN_ID_DEN_ALIEN_BASIC_07;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count++].count = 1;
        trigger_time_ms += 800;
        offset += 0x270;
        ++toggle;
    }

    *count = entry_count;
}
