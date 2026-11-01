// 0x406900 stores one world pickup. The six IDs are registered at startup.
#include "crimsonland_types.h"
extern "C" {
extern game_mode_id_t config_game_mode;
extern player_state_t player_state_table[2];
extern int current_player_index, freeware_arena_width, freeware_arena_height;
extern int freeware_bonus_count, freeware_pickup_id, freeware_pickup_weapon;
extern int freeware_bonus_fire, freeware_bonus_freeze, freeware_bonus_weapon;
extern int freeware_bonus_nuke, freeware_bonus_shield, freeware_bonus_time;
extern vec2f_t freeware_pickup_position;
extern float freeware_pickup_time;
int crt_rand();
}
extern "C" void bonus_spawn_at(const vec2f_t *pos) {
#if !defined(FREEWARE_EDITION) || FREEWARE_EDITION != 10002
    if (config_game_mode == 3)
        return;
#endif
#if !defined(FREEWARE_EDITION) || FREEWARE_EDITION >= 10400
    if (pos->x < 32 || pos->x > freeware_arena_width - 32 || pos->y < 32 ||
        pos->y > freeware_arena_height - 32)
        return;
#endif
    freeware_pickup_position = *pos;
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10300
    int id = crt_rand() % 5;  // 0x403f0d. The Survival reroll below uses the registered count.
#else
    int id = crt_rand() % freeware_bonus_count;
#endif
    if (config_game_mode == 2)
        while (id == 2)
            id = crt_rand() % freeware_bonus_count;
    if (player_state_table[current_player_index].freeware.weapon == 1)
        id = 2;
    if (id == 0)
        freeware_pickup_id = freeware_bonus_fire;
    else if (id == 1)
        freeware_pickup_id = freeware_bonus_freeze;
    else if (id == 2) {
        freeware_pickup_id = freeware_bonus_weapon;
#if !defined(FREEWARE_EDITION) || FREEWARE_EDITION != 10002
        do {
            freeware_pickup_weapon = crt_rand() % 14 + 2;
        } while (freeware_pickup_weapon == player_state_table[current_player_index].freeware.weapon);
#endif
    } else if (id == 3)
        freeware_pickup_id = freeware_bonus_nuke;
    else if (id == 4)
        freeware_pickup_id = freeware_bonus_shield;
    else if (id == 5)
        freeware_pickup_id = freeware_bonus_time;
    freeware_pickup_time = 10;
}
