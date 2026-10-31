// Career spawn at 0x40f650, including the native occupied-slot retry.
#include "cl_build.h"
#if CL_BUILD == 10400
#include "crimsonland_types.h"
extern "C" {
extern creature_t creature_pool[512];
extern player_state_t player_state_table[2];
extern int current_player_index, creature_spawned_count;
int creature_alloc_slot();
int crt_rand();
int plaguebearer_spread_infection(int);
}
static __inline float unit(float value) { return value < 0 ? 0 : value > 1 ? 1 : value; }
extern "C" unsigned char creature_spawn_random(const vec2f_t *pos) {
    const int id = creature_alloc_slot();
    creature_t &c = creature_pool[id];
    c.position = *pos;
    if (plaguebearer_spread_infection(id))
        return false;

    c.plague_infected = 0;
    c.anim_phase = 0;
    c.freeware.type = crt_rand() % 2 == 0 ? 2 : 1;
    c.active = 1;
    c.freeware.force_target = 0;
    c.death_timer = 16;
    vec2f_t zero = {0, 0};
    c.velocity = zero;
    int xp = player_state_table[current_player_index].freeware.experience;
    c.freeware.heading = (crt_rand() % 314) * .01f;
    c.freeware.move_speed = xp * (1.f / 21000) + .8f;
    if (c.freeware.move_speed > 3)
        c.freeware.move_speed = 3;
    c.health = xp * .00125f + 52;
    c.freeware.reward = xp * .00002f + (crt_rand() % 10 + 87);
    c.freeware.attack_cooldown = 0;
    c.freeware.color.r = 1.f - 1.f / (xp + 1.f);
    c.freeware.color.g = (crt_rand() % 10) * .01f + .9f;
    c.freeware.color.b = (crt_rand() % 10) * .01f + .7f;
    c.freeware.color.a = 1;
    if (crt_rand() % 180 < 2) {
        c.health = 65;
        c.freeware.color.r = .9f;
        c.freeware.color.g = .4f;
        c.freeware.color.b = .4f;
        c.freeware.color.a = 1;
        c.freeware.reward = 320;
    } else if (crt_rand() % 240 < 2) {
        c.health = 85;
        c.freeware.color.r = .4f;
        c.freeware.color.g = .9f;
        c.freeware.color.b = .4f;
        c.freeware.color.a = 1;
        c.freeware.reward = 420;
    } else if (crt_rand() % 360 < 2) {
        c.health = 125;
        c.freeware.color.r = .4f;
        c.freeware.color.g = .4f;
        c.freeware.color.b = .9f;
        c.freeware.color.a = 1;
        c.freeware.reward = 520;
    }
    c.freeware.size = float(crt_rand() % 28 + 42);
    if (crt_rand() % 1320 < 4) {
        c.freeware.size = 84;
        c.health += 230;
        c.freeware.color.r = .84f;
        c.freeware.color.g = .24f;
        c.freeware.color.b = .89f;
        c.freeware.color.a = 1;
        c.freeware.reward = 600;
    }
    if (crt_rand() % 1620 < 4) {
        c.freeware.size = 92;
        c.health += 2230;
        c.freeware.color.r = .94f;
        c.freeware.color.g = .84f;
        c.freeware.color.b = .29f;
        c.freeware.color.a = 1;
        c.freeware.reward = 900;
    }
    c.freeware.contact_damage = c.freeware.size * (1.f / 10.5f);
    c.ai_mode = 1;
    c.freeware.color.r = unit(c.freeware.color.r);
    c.freeware.color.g = unit(c.freeware.color.g);
    c.freeware.color.b = unit(c.freeware.color.b);
    c.freeware.color.a = unit(c.freeware.color.a);

    ++creature_spawned_count;
    return true;
}
#endif
