#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" {
extern int config_player_count;
extern float bonus_update_phase_accumulator;

void bonus_apply(int player_index, bonus_entry_t *bonus);
}

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    return (float)sqrt(distance_sq);
}

extern "C" void bonus_update(void)
{
    if (render_pass_mode == 0) {
        return;
    }

    const float pickup_radius = 26.0f;
    float pickup_lifetime = 0.5f;
    for (int bonus_index = 0; bonus_index < 16; ++bonus_index) {
        bonus_entry_t *bonus = &bonus_pool[bonus_index];
        if (bonus->bonus_id != BONUS_ID_NONE) {
            unsigned char state = bonus->state;
            bonus->time.time_left = state != 0
                ? bonus->time.time_left - frame_dt * 3.0f
                : bonus->time.time_left - frame_dt;

            if (state == 0 && config_game_mode == GAME_MODE_TUTORIAL) {
                bonus->time.time_left = 5.0f;
            }
            if (bonus->time.time_left < 0.0f) {
                bonus->bonus_id = BONUS_ID_NONE;
            }

            if (state == 0) {
                render_overlay_player_index = 0;
                if (config_player_count > 0) {
                    int player_index;
                    int player_count;
                    do {
                        player_index = render_overlay_player_index;
                        player_count = config_player_count;
                        if (vec2_distance(
                                (vec2f_t *)&bonus->time.pos_x,
                                (vec2f_t *)&player_state_table[player_index].pos_x)
                            < pickup_radius) {
                            bonus_apply(player_index, bonus);
                            player_count = config_player_count;
                            player_index = render_overlay_player_index;
                            bonus->state = 1;
                            bonus->time.time_left = pickup_lifetime;
                        }
                        ++player_index;
                        render_overlay_player_index = player_index;
                    } while (player_index < player_count);
                }
            }
        }
    }

    render_overlay_player_index = 0;
    if (bonus_freeze_timer > 0.0f) {
        bonus_freeze_timer -= frame_dt;
    } else {
        bonus_freeze_timer = 0.0f;
    }

    if (bonus_double_xp_timer > 0.0f) {
        bonus_double_xp_timer -= frame_dt;
    } else {
        bonus_double_xp_timer = 0.0f;
    }

    if (bonus_update_phase_accumulator >= 0.0f) {
        bonus_update_phase_accumulator =
            (bonus_update_phase_accumulator + 1.0f) * frame_dt * 1.8f
            + bonus_update_phase_accumulator;
    }
}
