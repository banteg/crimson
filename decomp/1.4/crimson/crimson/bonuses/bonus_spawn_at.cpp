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
    if (config_game_mode == 3 || pos->x < 32 || pos->x > freeware_arena_width - 32 || pos->y < 32 ||
        pos->y > freeware_arena_height - 32)
        return;
    freeware_pickup_position = *pos;
    int id = crt_rand() % freeware_bonus_count;
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
        do {
            freeware_pickup_weapon = crt_rand() % 14 + 2;
        } while (freeware_pickup_weapon == player_state_table[current_player_index].freeware.weapon);
    } else if (id == 3)
        freeware_pickup_id = freeware_bonus_nuke;
    else if (id == 4)
        freeware_pickup_id = freeware_bonus_shield;
    else if (id == 5)
        freeware_pickup_id = freeware_bonus_time;
    freeware_pickup_time = 10;
}
