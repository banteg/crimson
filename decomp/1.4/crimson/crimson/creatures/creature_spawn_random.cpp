// Career spawn at 0x4062e0 (1.0.2), 0x40b550 (1.3.0) and 0x40f650 (1.4.0).
#include "freeware_edition.h"
#include "crimsonland_types.h"
extern "C" {
extern creature_t creature_pool[512];
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
#define PLAYER_XP player_state_table[current_player_index].freeware.experience
#else
extern freeware_player_t player_state_table[2];
#define PLAYER_XP player_state_table[current_player_index].experience
#endif
extern int current_player_index, creature_spawned_count;
int creature_alloc_slot();
int crt_rand();
int plaguebearer_spread_infection(int);
}
static __inline void clamp_unit(float &value) {
    if (value < 0)
        value = 0;
    else if (value > 1)
        value = 1;
}
static __inline void clamp_color(effect_color_t &color) {
    clamp_unit(color.r);
    clamp_unit(color.g);
    clamp_unit(color.b);
    clamp_unit(color.a);
}
static __inline float scaled_xp(int xp, float scale) {
    // x87 FILD retains the integer until the first (single-precision) arithmetic operation.
#ifdef CRIMSON_FREEWARE_CLIENT
    return (float)((double)xp * scale);
#else
    return xp * scale;
#endif
}
static __inline void set_tint(effect_color_t &color, float r, float g, float b) {
    effect_color_t tint = {r, g, b, 1.f};
    color = tint;
}
extern "C" unsigned char creature_spawn_random(const vec2f_t *pos) {
    const int id = creature_alloc_slot();
    creature_pool[id].position = *pos;
    if (plaguebearer_spread_infection(id))
        return false;

    creature_pool[id].plague_infected = 0;
#if CL_BUILD == 10002
    creature_pool[id].plague_timer = 0;
#else
    creature_pool[id].anim_phase = 0;
#endif
    creature_pool[id].freeware.type = 1;
    if (crt_rand() % 2 == 0)
        creature_pool[id].freeware.type = 2;
    creature_pool[id].active = 1;
    creature_pool[id].freeware.force_target = 0;
    creature_pool[id].death_timer = 16;
    vec2f_t zero = {0, 0};
#if FREEWARE_EDITION == 10002
    creature_pool[id].health = 50;
#endif
    creature_pool[id].velocity = zero;
    creature_pool[id].freeware.heading = (crt_rand() % 314) * .01f;
#if FREEWARE_EDITION == 10002
    creature_pool[id].freeware.move_speed = scaled_xp(PLAYER_XP, 1.f / 15000) + 1;
    if (creature_pool[id].freeware.move_speed > 5)
        creature_pool[id].freeware.move_speed = 5;
    creature_pool[id].freeware.reward = crt_rand() % 10 + 120;
#else
    creature_pool[id].freeware.move_speed = scaled_xp(PLAYER_XP, 1.f / 21000) + .8f;
    if (creature_pool[id].freeware.move_speed > 3)
        creature_pool[id].freeware.move_speed = 3;
    creature_pool[id].health = scaled_xp(PLAYER_XP, .00125f) + 52;
    creature_pool[id].freeware.reward = (float)PLAYER_XP * .00002f + (crt_rand() % 10 + 87);
#endif
    creature_pool[id].freeware.attack_cooldown = 0;
    creature_pool[id].freeware.color.r = 1.f - 1.f / ((float)PLAYER_XP + 1.f);
    creature_pool[id].freeware.color.g = (crt_rand() % 10) * .01f + .9f;
    creature_pool[id].freeware.color.b = (crt_rand() % 10) * .01f + .7f;
    creature_pool[id].freeware.color.a = 1;
    if (crt_rand() % 180 < 2) {
        creature_pool[id].health = 65;
        set_tint(creature_pool[id].freeware.color, .9f, .4f, .4f);
        creature_pool[id].freeware.reward = 320;
    } else if (crt_rand() % 240 < 2) {
        creature_pool[id].health = 85;
        set_tint(creature_pool[id].freeware.color, .4f, .9f, .4f);
        creature_pool[id].freeware.reward = 420;
    } else if (crt_rand() % 360 < 2) {
        creature_pool[id].health = 125;
        set_tint(creature_pool[id].freeware.color, .4f, .4f, .9f);
        creature_pool[id].freeware.reward = 520;
    }
    creature_pool[id].freeware.size = (float)(crt_rand() % 28) + 42.f;
    if (crt_rand() % 1320 < 4) {
        creature_pool[id].freeware.size = 84;
        creature_pool[id].health += 230;
        set_tint(creature_pool[id].freeware.color, .84f, .24f, .89f);
        creature_pool[id].freeware.reward = 600;
    }
    if (crt_rand() % 1620 < 4) {
        creature_pool[id].freeware.size = 92;
        creature_pool[id].health += 2230;
        set_tint(creature_pool[id].freeware.color, .94f, .84f, .29f);
        creature_pool[id].freeware.reward = 900;
    }
    creature_pool[id].freeware.contact_damage = creature_pool[id].freeware.size * (1.f / 10.5f);
#if FREEWARE_EDITION >= 10400
    creature_pool[id].ai_mode = 1;
#endif
    clamp_color(creature_pool[id].freeware.color);

    ++creature_spawned_count;
    return true;
}
