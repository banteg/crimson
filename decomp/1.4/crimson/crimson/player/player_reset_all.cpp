// 1.0.2 resets the current player. The later freeware builds reset both and restore the index.
#include "freeware_level.h"
#if CL_BUILD == 10002
namespace {
struct reset_point {
    vec2f_t value;
    reset_point(float x, float y) {
        value.x = x;
        value.y = y;
    }
};
}
#endif

extern "C" {
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
#define PLAYER(i) player_state_table[i].freeware
#else
extern freeware_player_t player_state_table[2];
#define PLAYER(i) player_state_table[i]
#endif
extern creature_t creature_pool[];
extern game_mode_id_t config_game_mode;
extern int freeware_arena_width, freeware_arena_height, freeware_pickup_id, freeware_no_pickup;
extern float freeware_elapsed_seconds, freeware_pickup_time, freeware_berserk_timer;
extern vec2f_t freeware_aim_screen;
extern int current_player_index;
#define P PLAYER(current_player_index)
void player_reset_all() {
#if CL_BUILD == 10002
    P.plaguebearer = 0;
    freeware_elapsed_seconds = 0;
    freeware_pickup_id = freeware_no_pickup;
    P.clip_size = 30;
    P.health = 100;
    reset_point start(freeware_arena_width * .5f, freeware_arena_height * .5f);
    P.position = start.value;
    P.size = 48;
    P.speed_multiplier = 2;
    P.level = 1;
    P.heading = 0;
    P.experience = 0;
    P.spread = 1;
    P.move_speed = 0;
    P.ammo = 30;
    P.reload = 0;
    P.weapon = 1;
    P.previous_weapon = 0;
    reset_point aim(320, 140);
    freeware_aim_screen = aim.value;
    freeware_pickup_time = 0;
    for (int i = 0; i < 32; ++i)
        P.perks[i] = 0;
    for (int j = 0; j < 128; ++j)
        creature_pool[j].plague_infected = 0;
#else
    freeware_elapsed_seconds = 0;
    freeware_pickup_time = 0;
    freeware_pickup_id = freeware_no_pickup;
    int saved_index = current_player_index;

    current_player_index = 0;
    do {
        freeware_berserk_timer = 0;
        P.shield = 0;
        P.control_reserved = 0;
        P.plaguebearer = 0;
        if (config_game_mode != 3) {
            vec2f_t center = {freeware_arena_width * .5f, freeware_arena_height * .5f};
            P.position = center;
        } else
            P.position = freeware_current_map->start;
        P.health = 100;
        if (current_player_index == 1) {
            vec2f_t &position = PLAYER(1).position;
            vec2f_t delta = {80.f, 0.f};
            position.x += delta.x;
            position.y += delta.y;
        }
        P.size = 48;
        P.speed_multiplier = 2;
        P.level = 1;
        P.heading = freeware_current_map->start_heading;
        P.experience = 0;
        P.displayed_experience = 0;
        P.spread = 1;
        P.move_speed = 0;
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10002
        P.ammo = P.clip_size = 30;
#else
        P.ammo = 10;
        P.clip_size = 10;
#endif
        P.reload_duration = 1;
        P.reload = 0;
        P.cooldown = .8f;
        P.weapon = 1;
        P.previous_weapon = 0;
        vec2f_t aim = {320.f, 140.f};
        freeware_aim_screen = aim;
        for (int k = 0; k < sizeof(P.perks) / sizeof(P.perks[0]); ++k)
            P.perks[k] = 0;
        for (int j = 0; j < 512; ++j)
            creature_pool[j].plague_infected = 0;
        ++current_player_index;
    } while (current_player_index < 2);
    current_player_index = saved_index;
#endif
}
#undef P
#undef PLAYER
}
