#include <math.h>
#include "crimsonland_gameplay.h"

extern "C" int player_apply_move_with_spawn_avoidance(
    int player_index,
    vec2f_t *pos,
    vec2f_t *delta)
{
    vec2f_t probe;
    creature_t *owner;
    float collision_radius;
    int alternate_weapon_count;
    creature_spawn_slot_t *slot;
    player_state_t *player = &player_state_table[player_index];

    alternate_weapon_count = perk_count_get(perk_id_alternate_weapon);
    if (alternate_weapon_count != 0) {
        delta->x = delta->x * 0.8f;
        delta->y = delta->y * 0.8f;
    }

    pos->x = pos->x + delta->x;
    pos->y = pos->y + delta->y;
    slot = creature_spawn_slot_table;
    do {
        owner = slot->owner;
        if (owner != 0
            && (collision_radius = (owner->size + player->size) * 0.33333334f,
                probe.x = owner->pos_x - pos->x,
                probe.y = owner->pos_y - pos->y,
                (float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius)) {
            pos->x = pos->x - delta->x;
            pos->y = pos->y - delta->y;
            probe.x = owner->pos_x - pos->x;
            probe.y = owner->pos_y - pos->y;
            if ((float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius) {
                pos->x = pos->x + delta->x;
                pos->y = delta->y + pos->y;
            } else {
                pos->x = pos->x + delta->x;
                probe.x = owner->pos_x - pos->x;
                probe.y = owner->pos_y - pos->y;
                if ((float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius) {
                    pos->x = pos->x - delta->x;
                    pos->y = delta->y + pos->y;
                    probe.x = owner->pos_x - pos->x;
                    probe.y = owner->pos_y - pos->y;
                    if ((float)sqrt(probe.x * probe.x + probe.y * probe.y) <= collision_radius) {
                        pos->y = pos->y - delta->y;
                    }
                }
            }
        }
        ++slot;
    } while ((int)slot < (int)&creature_spawn_slot_table[0x20]);
    return 0;
}
