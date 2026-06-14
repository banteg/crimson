#include <math.h>
#include "crimsonland_gameplay.h"

extern "C" void player_apply_move_with_spawn_avoidance(int player_index, float *pos, float *delta)
{
    player_state_t *player = &player_state_table[player_index];

    if (perk_count_get(perk_id_alternate_weapon) != 0) {
        delta[0] = delta[0] * 0.8f;
        delta[1] = delta[1] * 0.8f;
    }

    pos[0] = pos[0] + delta[0];
    pos[1] = pos[1] + delta[1];

    creature_spawn_slot_t *slot = creature_spawn_slot_table;
    do {
        creature_t *owner = slot->owner;
        if (owner != 0) {
            float radius = (owner->size + player->size) * 0.33333334f;
            float dx = owner->pos_x - pos[0];
            float dy = owner->pos_y - pos[1];
            if ((float)sqrt(dx * dx + dy * dy) <= radius) {
                pos[0] = pos[0] - delta[0];
                float old_y = pos[1];
                float move_y = delta[1];
                pos[1] = old_y - move_y;

                float dx_y_only = owner->pos_x - pos[0];
                float dy_y_only = owner->pos_y - (old_y - move_y);
                float next_x = pos[0] + delta[0];
                if (radius < (float)sqrt(dx_y_only * dx_y_only + dy_y_only * dy_y_only)) {
                    pos[0] = next_x;
                    dx_y_only = owner->pos_x - next_x;
                    float dy_x_only = owner->pos_y - pos[1];
                    if ((float)sqrt(dx_y_only * dx_y_only + dy_x_only * dy_x_only) <= radius) {
                        pos[0] = next_x - delta[0];
                        old_y = delta[1] + pos[1];
                        pos[1] = old_y;
                        dx_y_only = owner->pos_x - pos[0];
                        dy_x_only = owner->pos_y - old_y;
                        if ((float)sqrt(dx_y_only * dx_y_only + dy_x_only * dy_x_only) <= radius) {
                            pos[1] = old_y - delta[1];
                        }
                    }
                } else {
                    pos[0] = next_x;
                    pos[1] = delta[1] + pos[1];
                }
            }
        }
        ++slot;
    } while ((int)slot < (int)&creature_spawn_slot_table[0x20]);
}
