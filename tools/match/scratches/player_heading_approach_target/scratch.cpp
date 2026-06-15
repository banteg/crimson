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
    player_state_t *player = &player_state_table[player_index];
    float heading = player->heading;

    while (heading < 0.0f) {
        heading = player->heading + 6.2831855f;
        player->heading = heading;
    }
    heading = player->heading;
    while (heading > 6.2831855f) {
        heading = player->heading - 6.2831855f;
        player->heading = heading;
    }

    float direct = abs_bits(target_heading - player->heading);
    float high = player->heading;
    if (player->heading < target_heading) {
        high = target_heading;
    }
    float low = player->heading;
    if (target_heading < player->heading) {
        low = target_heading;
    }
    float wrapped = abs_bits((6.2831855f - high) + low);
    float amount = wrapped;
    if (direct < wrapped) {
        amount = direct;
    }

    if (direct <= wrapped) {
        if (player->heading < target_heading) {
            player_heading_turn_delta = frame_dt * amount * 5.0f;
            goto apply;
        }
    } else if (target_heading < player->heading) {
        player_heading_turn_delta = frame_dt * amount * 5.0f;
        goto apply;
    }
    player_heading_turn_delta = frame_dt * amount * -5.0f;

apply:
    player->heading = player_heading_turn_delta + player->heading;
    return amount;
}
