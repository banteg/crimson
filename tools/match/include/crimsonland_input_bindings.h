#ifndef CRIMSONLAND_INPUT_BINDINGS_H
#define CRIMSONLAND_INPUT_BINDINGS_H

#include "crimsonland_types.h"

extern "C" {
extern crimson_cfg_t config_blob;
extern player_state_t player_state_table[2];
}

static inline void config_apply_player_bindings(void)
{
    for (int player_index = 0; player_index < 2; ++player_index) {
        // Each saved row has 16 slots. The two axis pairs are stored Y before X.
        int key = player_index * 16;
        player_state_table[player_index].input.move_key_forward = config_blob.player_keys[key++];
        player_state_table[player_index].input.move_key_backward = config_blob.player_keys[key++];
        player_state_table[player_index].input.turn_key_left = config_blob.player_keys[key++];
        player_state_table[player_index].input.turn_key_right = config_blob.player_keys[key++];
        player_state_table[player_index].input.fire_key = config_blob.player_keys[key++];
        player_state_table[player_index].input.key_reserved_0 = config_blob.player_keys[key++];
        player_state_table[player_index].input.key_reserved_1 = config_blob.player_keys[key++];
        player_state_table[player_index].input.aim_key_left = config_blob.player_keys[key++];
        player_state_table[player_index].input.aim_key_right = config_blob.player_keys[key++];
        player_state_table[player_index].input.axis_aim_y = config_blob.player_keys[key++];
        player_state_table[player_index].input.axis_aim_x = config_blob.player_keys[key++];
        player_state_table[player_index].input.axis_move_y = config_blob.player_keys[key++];
        player_state_table[player_index].input.axis_move_x = config_blob.player_keys[key];
    }
}

#endif
