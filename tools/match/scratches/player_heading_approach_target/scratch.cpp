#include "crimsonland_gameplay.h"

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" float player_heading_approach_target(float target_heading)
{
    int player_index = render_overlay_player_index;
    float heading = player_state_table[player_index].heading;

    while (heading < 0.0f) {
        heading = player_state_table[player_index].heading + 6.2831855f;
        player_state_table[player_index].heading = heading;
    }
    heading = player_state_table[player_index].heading;
    while (heading > 6.2831855f) {
        heading = player_state_table[player_index].heading - 6.2831855f;
        player_state_table[player_index].heading = heading;
    }

    float direct = abs_bits(target_heading - player_state_table[player_index].heading);
    float high = player_state_table[player_index].heading;
    if (target_heading > high) {
        high = target_heading;
    }
    float low = player_state_table[player_index].heading;
    if (target_heading < low) {
        low = target_heading;
    }
    float wrapped = abs_bits((6.2831855f - high) + low);
    float amount;
    if (direct < wrapped) {
        amount = direct;
    } else {
        amount = wrapped;
    }

    if (direct > wrapped) {
        player_heading_turn_delta = target_heading < player_state_table[player_index].heading
            ? frame_dt * amount * 5.0f
            : frame_dt * amount * -5.0f;
    } else {
        player_heading_turn_delta = target_heading > player_state_table[player_index].heading
            ? frame_dt * amount * 5.0f
            : frame_dt * amount * -5.0f;
    }
    player_state_table[player_index].heading =
        player_heading_turn_delta + player_state_table[player_index].heading;
    return amount;
}
