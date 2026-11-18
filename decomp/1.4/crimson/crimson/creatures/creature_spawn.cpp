#include "crimsonland_gameplay.h"

extern "C" float freeware_elapsed_seconds;

#if CL_BUILD == 10002 || (defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10002)
// 0x4067a0. Native callers inspect AL. The shared client needs the allocated slot.
extern "C" int plaguebearer_spread_infection(int);
#ifdef CRIMSON_FREEWARE_CLIENT
typedef int spawn_result_t;
#else
typedef bool spawn_result_t;
#endif
extern "C" spawn_result_t creature_spawn(const vec2f_t *position, const effect_color_t *tint, int type) {
    int index = creature_alloc_slot();
    creature_pool[index].position = *position;
    if (plaguebearer_spread_infection(index)) {
#ifdef CRIMSON_FREEWARE_CLIENT
        return -1;
#else
        return 0;
#endif
    }
    creature_pool[index].plague_infected = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
    creature_pool[index].anim_phase = 0;
#else
    creature_pool[index].hit_flash_timer = 0;
#endif
    creature_pool[index].freeware.type = type;
    creature_pool[index].active = 1;
    creature_pool[index].freeware.force_target = 0;
    creature_pool[index].death_timer = 16;
    creature_pool[index].health = freeware_elapsed_seconds * .1f + 10;
    vec2f_t zero = {0, 0};
    creature_pool[index].velocity = zero;
    creature_pool[index].freeware.heading = (crt_rand() % 314) * .01f;
    creature_pool[index].freeware.move_speed = freeware_elapsed_seconds * .01f + 2.5f;
    creature_pool[index].freeware.reward = crt_rand() % 10 + 120;
    creature_pool[index].freeware.attack_cooldown = 0;
    creature_pool[index].freeware.color = *tint;
    creature_pool[index].freeware.size = freeware_elapsed_seconds * .01f + 47;
    creature_pool[index].freeware.contact_damage = 4;
    ++creature_spawned_count;
#ifdef CRIMSON_FREEWARE_CLIENT
    return index;
#else
    return 1;
#endif
}
#else

// Level Test has fixed monsters. Career and Survival scale with elapsed seconds.
extern "C" int creature_spawn(const vec2f_t *position, const effect_color_t *tint, int type)
{
    int index = creature_alloc_slot();
    creature_pool[index].position = *position;
    creature_pool[index].plague_infected = 0;
    creature_pool[index].anim_phase = 0.0f;
    creature_pool[index].freeware.type = type;
    creature_pool[index].active = 1;
    creature_pool[index].freeware.force_target = 0;
#if CL_BUILD >= 10400 && (!defined(FREEWARE_EDITION) || FREEWARE_EDITION >= 10400)
    creature_pool[index].ai_mode = 1;
#else
    creature_pool[index].ai_mode = 0;
#endif
    creature_pool[index].activation_radius = 128.0f;
    creature_pool[index].death_timer = 16.0f;
    if (config_game_mode == 3) {
        creature_pool[index].health = 300.0f;
    } else {
        creature_pool[index].health = freeware_elapsed_seconds * 0.1f + 10.0f;
    }
    vec2f_t velocity = {0.0f, 0.0f};
    creature_pool[index].velocity = velocity;
    creature_pool[index].freeware.heading = (float)(crt_rand() % 314) * 0.01f;
    if (config_game_mode == 3) {
        creature_pool[index].freeware.move_speed = 2.5f;
    } else {
        creature_pool[index].freeware.move_speed = freeware_elapsed_seconds * 0.01f + 2.5f;
    }
    creature_pool[index].freeware.reward = (double)(crt_rand() % 30 + 140);
    creature_pool[index].freeware.attack_cooldown = 0.0f;
    creature_pool[index].freeware.color = *tint;
    if (config_game_mode == 3) {
        creature_pool[index].freeware.size = 48.0f;
    } else {
        creature_pool[index].freeware.size = freeware_elapsed_seconds * 0.01f + 47.0f;
    }
    creature_pool[index].freeware.contact_damage = 4.0f;
    ++creature_spawned_count;
    return index;
}
#endif
