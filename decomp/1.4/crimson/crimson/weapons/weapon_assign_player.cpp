#include "crimsonland_types.h"

#if CL_BUILD == 10400
extern "C" player_state_t player_state_table[2];
#define PLAYER(i) player_state_table[i].freeware
#else
extern "C" freeware_player_t player_state_table[2];
#define PLAYER(i) player_state_table[i]
#endif
extern "C" unsigned char freeware_secret_weapon_unlocked;

extern "C" void weapon_assign_player(int index, int weapon)
{
#if CL_BUILD == 10400
    if (!freeware_secret_weapon_unlocked && (weapon == 18 || weapon == 17))
        return;
#endif
    PLAYER(index).weapon = weapon;
    if (weapon == 1)
        PLAYER(index).clip_size = 15.0f;
    else if (weapon == 2)
        PLAYER(index).clip_size = 25.0f;
    else if (weapon == 3)
        PLAYER(index).clip_size = 15.0f;
    else if (weapon == 4)
        PLAYER(index).clip_size = 15.0f;
    else if (weapon == 6)
        PLAYER(index).clip_size = 30.0f;
    else if (weapon == 5)
        PLAYER(index).clip_size = 30.0f;
    else if (weapon == 7)
        PLAYER(index).clip_size = 20.0f;
    else if (weapon == 8)
        PLAYER(index).clip_size = 8.0f;
    else if (weapon == 9)
        PLAYER(index).clip_size = 30.0f;
    else if (weapon == 10)
        PLAYER(index).clip_size = 5.0f;
    else if (weapon == 11)
        PLAYER(index).clip_size = 5.0f;
    else if (weapon == 12)
        PLAYER(index).clip_size = 8.0f;
    else if (weapon == 13)
        PLAYER(index).clip_size = 100.0f;
    else if (weapon == 14)
        PLAYER(index).clip_size = 6.0f;
    else if (weapon == 17)
        PLAYER(index).clip_size = 20.0f;
    else if (weapon == 15)
        PLAYER(index).clip_size = 30.0f;
#if CL_BUILD == 10400
    else if (weapon == 16)
        PLAYER(index).clip_size = 5.0f;
    else if (weapon == 18)
        PLAYER(index).clip_size = 10.0f;
    else if (weapon == 20)
        PLAYER(index).clip_size = 3.0f;
    else if (weapon == 19)
        PLAYER(index).clip_size = 15.0f;
#else
    else if (weapon == 16)
        PLAYER(index).clip_size = 1.0f;
#endif
    PLAYER(index).ammo = PLAYER(index).clip_size;
}
