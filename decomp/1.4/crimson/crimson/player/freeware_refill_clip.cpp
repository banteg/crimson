// crimson.exe 1.4.0, 0x4067e0.
#include "crimsonland_types.h"
extern "C" {
extern player_state_t player_state_table[2];
extern int current_player_index;
void freeware_refill_clip() {
    player_state_table[current_player_index].freeware.ammo =
        player_state_table[current_player_index].freeware.clip_size;
    player_state_table[current_player_index].freeware.cooldown = -.1f;
}
}
