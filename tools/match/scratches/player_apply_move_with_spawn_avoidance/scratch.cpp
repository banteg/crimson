#include <math.h>
#include "crimsonland_gameplay.h"

extern "C" int player_apply_move_with_spawn_avoidance(int player_index, float *pos, float *delta)
{
    vec2f_t probe;
    creature_t *owner;
    float collision_radius;
    int alternate_weapon_count;
    creature_spawn_slot_t *slot;
    player_state_t *player = &player_state_table[player_index];

    alternate_weapon_count = perk_count_get(perk_id_alternate_weapon);
    if (alternate_weapon_count != 0) {
        delta[0] = delta[0] * 0.8f;
        delta[1] = delta[1] * 0.8f;
    }

    pos[0] = pos[0] + delta[0];
    pos[1] = pos[1] + delta[1];
    slot = creature_spawn_slot_table;
    do {
        owner = slot->owner;
        if (owner != 0
            && (collision_radius = (owner->size + player->size) * 0.33333334f,
                probe.x = owner->pos_x - pos[0],
                probe.y = owner->pos_y - pos[1],
                (float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius)) {
            pos[0] = pos[0] - delta[0];
            pos[1] = pos[1] - delta[1];
            probe.x = owner->pos_x - pos[0];
            probe.y = owner->pos_y - pos[1];
            if ((float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius) {
                pos[0] = pos[0] + delta[0];
                pos[1] = delta[1] + pos[1];
            } else {
                pos[0] = pos[0] + delta[0];
                probe.x = owner->pos_x - pos[0];
                probe.y = owner->pos_y - pos[1];
                if ((float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius) {
                    pos[0] = pos[0] - delta[0];
                    pos[1] = delta[1] + pos[1];
                    probe.x = owner->pos_x - pos[0];
                    probe.y = owner->pos_y - pos[1];
                    if ((float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius) {
                        pos[1] = pos[1] - delta[1];
                    }
                }
            }
        }
        ++slot;
    } while ((int)slot < (int)&creature_spawn_slot_table[0x20]);
    return 0;
}
