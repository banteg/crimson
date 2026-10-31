#include "crimsonland_gameplay.h"

#if CL_BUILD >= 10300
extern "C" float freeware_elapsed_seconds;

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
#if CL_BUILD >= 10400
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
