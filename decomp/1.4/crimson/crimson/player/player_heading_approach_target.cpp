#include "freeware_edition.h"
#include "crimsonland_types.h"
#include <math.h>

extern "C" {
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
#else
extern freeware_player_t player_state_table[2];
#endif
extern int current_player_index;
extern float frame_dt;
float freeware_float_min(float, float);
float freeware_float_max(float, float);
}

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" float player_heading_approach_target(float target_heading)
{
    int player_index = current_player_index;
    while (player_state_table[player_index].heading < 0.0f) {
        player_state_table[player_index].heading += 6.2831855f;
    }
    while (player_state_table[player_index].heading > 6.2831855f) {
        player_state_table[player_index].heading -= 6.2831855f;
    }

#if FREEWARE_EDITION < 10400
    float heading = player_state_table[player_index].heading;
    float direct = (float)fabs((float)(target_heading - heading));
    float wrapped = (float)fabs((6.2831855f - freeware_float_max(target_heading, heading))
                                + freeware_float_min(target_heading, player_state_table[current_player_index].heading));
    float amount = freeware_float_min(direct, wrapped);
    const int &turn_index = current_player_index;
#else
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
    const int turn_index = player_index;
#endif
    if (direct > wrapped) {
        if (target_heading < player_state_table[turn_index].heading) {
            player_state_table[turn_index].heading += frame_dt * amount * 5.0f;
            return amount;
        } else {
            player_state_table[turn_index].heading -= frame_dt * amount * 5.0f;
            return amount;
        }
    } else {
        if (target_heading > player_state_table[turn_index].heading) {
            player_state_table[turn_index].heading += frame_dt * amount * 5.0f;
            return amount;
        } else {
            player_state_table[turn_index].heading -= frame_dt * amount * 5.0f;
            return amount;
        }
    }
}
