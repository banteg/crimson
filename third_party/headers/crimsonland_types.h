/* Crimsonland types derived from static analysis. */
#ifndef CRIMSONLAND_TYPES_H
#define CRIMSONLAND_TYPES_H

typedef struct weapon_stats_t {
    unsigned char _pad[0x7c];
} weapon_stats_t;

typedef struct music_channel_t {
    unsigned char _pad[0x84];
} music_channel_t;

typedef struct player_input_t {
    int move_key_forward;
    int move_key_backward;
    int turn_key_left;
    int turn_key_right;
    int fire_key;
    int key_reserved_0;
    int key_reserved_1;
    int aim_key_left;
    int aim_key_right;
    int axis_aim_x;
    int axis_aim_y;
    int axis_move_x;
    int axis_move_y;
} player_input_t;

typedef struct player_state_t {
    unsigned char _pad0[0x308];
    player_input_t input;
    unsigned char _pad1[0x24];
} player_state_t;

#endif
