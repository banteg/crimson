#include "crimsonland_types.h"

extern "C" player_state_t player_state_table[2];
extern "C" unsigned char freeware_secret_weapon_unlocked;

extern "C" void weapon_assign_player(int index, int weapon)
{
    if (!freeware_secret_weapon_unlocked && (weapon == 18 || weapon == 17))
        return;
    player_state_table[index].freeware.weapon = weapon;
    if (weapon == 1)
        player_state_table[index].freeware.clip_size = 15.0f;
    else if (weapon == 2)
        player_state_table[index].freeware.clip_size = 25.0f;
    else if (weapon == 3)
        player_state_table[index].freeware.clip_size = 15.0f;
    else if (weapon == 4)
        player_state_table[index].freeware.clip_size = 15.0f;
    else if (weapon == 6)
        player_state_table[index].freeware.clip_size = 30.0f;
    else if (weapon == 5)
        player_state_table[index].freeware.clip_size = 30.0f;
    else if (weapon == 7)
        player_state_table[index].freeware.clip_size = 20.0f;
    else if (weapon == 8)
        player_state_table[index].freeware.clip_size = 8.0f;
    else if (weapon == 9)
        player_state_table[index].freeware.clip_size = 30.0f;
    else if (weapon == 10)
        player_state_table[index].freeware.clip_size = 5.0f;
    else if (weapon == 11)
        player_state_table[index].freeware.clip_size = 5.0f;
    else if (weapon == 12)
        player_state_table[index].freeware.clip_size = 8.0f;
    else if (weapon == 13)
        player_state_table[index].freeware.clip_size = 100.0f;
    else if (weapon == 14)
        player_state_table[index].freeware.clip_size = 6.0f;
    else if (weapon == 17)
        player_state_table[index].freeware.clip_size = 20.0f;
    else if (weapon == 15)
        player_state_table[index].freeware.clip_size = 30.0f;
    else if (weapon == 16)
        player_state_table[index].freeware.clip_size = 5.0f;
    else if (weapon == 18)
        player_state_table[index].freeware.clip_size = 10.0f;
    else if (weapon == 20)
        player_state_table[index].freeware.clip_size = 3.0f;
    else if (weapon == 19)
        player_state_table[index].freeware.clip_size = 15.0f;
    player_state_table[index].freeware.ammo = player_state_table[index].freeware.clip_size;
}
