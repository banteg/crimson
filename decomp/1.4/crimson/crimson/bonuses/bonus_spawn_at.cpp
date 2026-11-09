// 1.3.0 at 0x403ee0 and 1.4.0 at 0x406900 store one world pickup.
#include "freeware_edition.h"
#include "crimsonland_types.h"
extern "C" {
extern game_mode_id_t config_game_mode;
#if CL_BUILD == 10300
extern freeware_player_t player_state_table[2];
#define PLAYER player_state_table[current_player_index]
#else
extern player_state_t player_state_table[2];
#define PLAYER player_state_table[current_player_index].freeware
#endif
extern int current_player_index, freeware_arena_width, freeware_arena_height;
extern int freeware_bonus_count, freeware_pickup_id, freeware_pickup_weapon;
extern int freeware_bonus_fire, freeware_bonus_freeze, freeware_bonus_weapon;
extern int freeware_bonus_nuke, freeware_bonus_shield, freeware_bonus_time;
extern vec2f_t freeware_pickup_position;
extern float freeware_pickup_time;
int crt_rand();
}
extern "C" void bonus_spawn_at(const vec2f_t *pos) {
#if FREEWARE_EDITION != 10002
    if (config_game_mode == 3)
        return;
#endif
#if FREEWARE_EDITION >= 10400
    if (pos->x < 32 || pos->x > freeware_arena_width - 32 || pos->y < 32 ||
        pos->y > freeware_arena_height - 32)
        return;
#endif
    freeware_pickup_position = *pos;
#if FREEWARE_EDITION == 10300
    int id = crt_rand() % 5;  // 0x403f0d. The Survival reroll below uses the registered count.
#else
    int id = crt_rand() % freeware_bonus_count;
#endif
    if (config_game_mode == 2)
        while (id == 2)
            id = crt_rand() % freeware_bonus_count;
    if (PLAYER.weapon == 1)
        id = 2;
    if (id == 0)
        freeware_pickup_id = freeware_bonus_fire;
    else if (id == 1)
        freeware_pickup_id = freeware_bonus_freeze;
    else if (id == 2) {
        freeware_pickup_id = freeware_bonus_weapon;
#if FREEWARE_EDITION != 10002
        do {
            freeware_pickup_weapon = crt_rand() % 14 + 2;
        } while (freeware_pickup_weapon == PLAYER.weapon);
#endif
    } else if (id == 3)
        freeware_pickup_id = freeware_bonus_nuke;
    else if (id == 4)
        freeware_pickup_id = freeware_bonus_shield;
    else if (id == 5)
        freeware_pickup_id = freeware_bonus_time;
    freeware_pickup_time = 10;
}
