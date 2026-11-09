// Crimsonland 1.0.2, 0x404b70..0x40508c. Creatures pursue the current player.
#include "cl_build.h"

#if CL_BUILD == 10002
#define PLAGUE_TIMER(slot) creature_pool[slot].plague_timer
#else
// The portable client stores this timer in its common creature record.
#define PLAGUE_TIMER(slot) creature_pool[slot].anim_phase
#endif
extern "C" void creature_update_all() {
    if (bonus_freeze_timer > 0)
        return;
    for (int slot = 0; slot < 128; ++slot) {
        if (!creature_pool[slot].active)
            continue;
        if (creature_pool[slot].death_timer == 16) {
            if (creature_pool[slot].plague_infected) {
                PLAGUE_TIMER(slot) -= frame_dt;
                if (PLAGUE_TIMER(slot) < 0) {
                    PLAGUE_TIMER(slot) = .5f;
                    creature_pool[slot].health -= 5;
                    if (creature_pool[slot].health < 0) {
                        PLAYER(current_player_index).experience += creature_pool[slot].freeware.reward;
                        creature_pool[slot].death_timer -= frame_dt;
                    }
                    fx_queue_add_random(&creature_pool[slot].position);
                }
            }

            vec2f_t *position = &creature_pool[slot].position;
            float dist = range(PLAYER(current_player_index).position, *position);
            float angle = (3.7f * slot) * (double)pi;
            creature_pool[slot].freeware.target.x =
                (float)cos(angle) * dist * .85f + PLAYER(current_player_index).position.x;
            creature_pool[slot].freeware.target.y =
                (float)sin(angle) * dist * .85f + PLAYER(current_player_index).position.y;
            creature_pool[slot].freeware.force_target = 0;
            if (range(creature_pool[slot].freeware.target, *position) < 15)
                creature_pool[slot].freeware.force_target = 1;
            creature_pool[slot].freeware.heading =
                (point(creature_pool[slot].freeware.target) - point(*position)).angle() + half_pi;
            creature_pool[slot].vel_x =
                (float)((double)frame_dt * (float)cos(creature_pool[slot].freeware.heading - half_pi)) *
                creature_pool[slot].freeware.move_speed * 30.f;
            creature_pool[slot].vel_y =
                (float)((double)frame_dt * (float)sin(creature_pool[slot].freeware.heading - half_pi)) *
                creature_pool[slot].freeware.move_speed * 30.f;
            position->x += creature_pool[slot].vel_x;
            double old_y = creature_pool[slot].pos_y;
            creature_pool[slot].pos_y = old_y + creature_pool[slot].vel_y;
            position->x +=
                (float)cos(creature_pool[slot].freeware.attack_cooldown * 12.566371f) * frame_dt * 10;
            creature_pool[slot].pos_y +=
                (float)sin(creature_pool[slot].freeware.attack_cooldown * 12.566371f) * frame_dt * 10;

            int other = plaguebearer_spread_infection(slot);
            if (other) {
                creature_pool[other].pos_x -= creature_pool[slot].vel_x;
                creature_pool[other].pos_y -= creature_pool[slot].vel_y;
                position->x += creature_pool[other].vel_x;
                creature_pool[slot].pos_y += creature_pool[other].vel_y;
            }

            creature_pool[slot].freeware.animation += frame_dt * creature_pool[slot].freeware.move_speed * 26;
            while (creature_pool[slot].freeware.animation > 31)
                creature_pool[slot].freeware.animation -= 31;
            creature_pool[slot].freeware.attack_cooldown -= frame_dt;
            if (creature_pool[slot].freeware.attack_cooldown < 0)
                creature_pool[slot].freeware.attack_cooldown = 0;

            float dx = position->x - PLAYER(current_player_index).position.x;
            float dy = creature_pool[slot].pos_y - PLAYER(current_player_index).position.y;
            const float contact = (float)sqrt(dx * dx + (double)dy * dy);
            dist = contact;
            if (dist < 100.f && PLAYER(current_player_index).perks[perk_id_radioactive] > 0) {
                PLAGUE_TIMER(slot) -= frame_dt * 1.5f;
                if (PLAGUE_TIMER(slot) < 0) {
                    PLAGUE_TIMER(slot) = .5f;
                    creature_pool[slot].health -= (100 - dist) * .3f;
                    if (creature_pool[slot].health < 0) {
                        PLAYER(current_player_index).experience += creature_pool[slot].freeware.reward;
                        creature_pool[slot].death_timer -= frame_dt;
                    }
                    fx_queue_add_random(position);
                }
            }

            if (dist < 20) {
                position->x -= creature_pool[slot].vel_x;
                creature_pool[slot].pos_y -= creature_pool[slot].vel_y;
            }
            if (dist < 30) {
                if (creature_pool[slot].freeware.attack_cooldown <= 0) {
                    sfx_play_panned(crt_rand() % 4 + 9, .45f, .5f);
                    if (freeware_berserk_timer >= 0)
                        PLAYER(current_player_index).health -= creature_pool[slot].freeware.contact_damage;

                    CreaturePoint delta =
                        point(PLAYER(current_player_index).position) - point(creature_pool[slot].position);
                    float inverse_length = 1.0f / (float)sqrt((delta.y * delta.y + delta.x * delta.x));
                    delta.x *= inverse_length;
                    delta.y *= inverse_length;
                    CreaturePoint mark = point(PLAYER(current_player_index).position) + delta * 3.0f;
                    fx_queue_add_random((vec2f_t *)&mark);
                    creature_pool[slot].freeware.attack_cooldown = 1;
                }
                if (PLAYER(current_player_index).plaguebearer)
                    creature_pool[slot].plague_infected = 1;
            }
        } else {
            creature_pool[slot].death_timer -= frame_dt * 28;
            creature_pool[slot].vel_x = (float)cos(creature_pool[slot].freeware.heading - half_pi) *
                                        creature_pool[slot].death_timer * frame_dt * 9;
            creature_pool[slot].vel_y = (float)sin(creature_pool[slot].freeware.heading - half_pi) *
                                        frame_dt * creature_pool[slot].death_timer * 9;
            creature_pool[slot].pos_x -= creature_pool[slot].vel_x;
            creature_pool[slot].pos_y -= creature_pool[slot].vel_y;
        }
    }
}
#undef PLAGUE_TIMER
