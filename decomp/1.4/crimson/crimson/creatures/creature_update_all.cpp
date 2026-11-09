#include "cl_build.h"
#include "freeware_edition.h"
#include "freeware_level.h"
#include <math.h>

extern "C" {
extern creature_t creature_pool[CL_BUILD == 10002 ? 128 : 512];
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
#define PLAYER(i) player_state_table[i].freeware
#else
extern freeware_player_t player_state_table[2];
#define PLAYER(i) player_state_table[i]
#endif
extern float frame_dt, bonus_freeze_timer, freeware_berserk_timer;
extern int current_player_index, perk_id_radioactive;
int plaguebearer_spread_infection(int);
int crt_rand();
int sfx_play_panned(int, float, float);
void fx_queue_add_random(const vec2f_t *);
}

namespace {
const float pi = 3.14159274f, half_pi = 1.57079637f;
static __forceinline float range(const vec2f_t &a, const vec2f_t &b) {
    float x = a.x - b.x, y = a.y - b.y;
    return (float)sqrt(x * x + y * y);
}

struct CreaturePoint {
    float x, y;
    CreaturePoint(float x_value, float y_value) : x(x_value), y(y_value) {}
    CreaturePoint operator-(const CreaturePoint &b) const { return CreaturePoint(x - b.x, y - b.y); }
    CreaturePoint operator+(const CreaturePoint &b) const { return CreaturePoint(x + b.x, y + b.y); }
    CreaturePoint operator*(float scale) const { return CreaturePoint(x * scale, y * scale); }
    float angle() const { return (float)atan2(y, x); }
};
static __forceinline const CreaturePoint &point(const vec2f_t &position) {
    return reinterpret_cast<const CreaturePoint &>(position);
}

} // namespace

#if FREEWARE_EDITION == 10002
#include "creature_update_early.inc"
#else
// 1.3.0: 0x409c80..0x40a3b8.  1.4.0: 0x40d8c0..0x40e05c.
extern "C" {
extern int plaguebearer_infection_count, perk_id_almost_invisible;
extern game_mode_id_t config_game_mode;
extern float freeware_simulation_clock;
extern unsigned char freeware_game_active;
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
float angle_approach(float *, float);
#if CL_BUILD == 10300
extern int perk_id_reserved_22;
#define CONTACT_IMMUNITY perk_id_reserved_22
void creature_handle_death(int, int);
#else
void creature_handle_death(int, int, unsigned char);
#define CONTACT_IMMUNITY 22
#endif
}
extern "C" void creature_update_all() {
    if (bonus_freeze_timer > 0)
        return;
    for (int slot = 0; slot < 512; ++slot) {
        if (!creature_pool[slot].active)
            continue;
        if (creature_pool[slot].health <= 0 && creature_pool[slot].death_timer == 16)
            creature_pool[slot].death_timer -= frame_dt;
        vec2f_t *position = &creature_pool[slot].position;
        float dist;
        {
            CreaturePoint offset =
                point(PLAYER(creature_pool[slot].freeware.player).position) - point(*position);
            float length = (float)sqrt(offset.x * offset.x + offset.y * offset.y);
            dist = length;
        }
        if (FREEWARE_EDITION == 10300 ? config_game_mode == 3 : config_game_mode != 2) {
            if (dist < creature_pool[slot].activation_radius)
                creature_pool[slot].ai_mode = 1;
            if (!creature_pool[slot].ai_mode)
                continue;
        }
        if (creature_pool[slot].hit_flash_timer != -1) {
            creature_pool[slot].hit_flash_timer += frame_dt;
            if (creature_pool[slot].hit_flash_timer > 4) {
                if (FREEWARE_EDITION == 10300 || freeware_game_active) {
                    effect_color_t color;
                    color.r = .8f;
                    color.g = .8f;
                    color.b = .8f;
                    color.a = 1.f;
                    int child = creature_spawn(position, &color, 1);
                    if (child != -1) {
                        creature_pool[child].freeware.size = 30;
                        creature_pool[child].freeware.move_speed *= .6f;
                    }
                }
                creature_pool[slot].hit_flash_timer -= 4;
            }
        }
        if (creature_pool[slot].hit_flash_timer > 2.5f)
            continue;
        if (PLAYER(creature_pool[slot].freeware.player).health <= 0)
            creature_pool[slot].freeware.player = 1 - creature_pool[slot].freeware.player;

        if (creature_pool[slot].death_timer == 16) {
            float &phase_timer = creature_pool[slot].anim_phase;
            if (creature_pool[slot].plague_infected) {
                phase_timer -= frame_dt;
                if (phase_timer < 0) {
                    phase_timer += .5f;
                    creature_pool[slot].health -= 15;
                    creature_pool[slot].ai_mode = 1;
                    if (creature_pool[slot].health < 0) {
                        ++plaguebearer_infection_count;
#if CL_BUILD == 10300
                        creature_handle_death(slot, current_player_index);
#else
                        creature_handle_death(slot, current_player_index, 1);
#endif
#if FREEWARE_EDITION >= 10400
                        sfx_play_panned(28, (crt_rand() % 70) * .1f + .3f, .5f);
#endif
                    }
                    fx_queue_add_random(position);
                }
            }

            float angle = (3.7f * slot) * (double)pi;
            creature_pool[slot].freeware.force_target = 0;
            if (config_game_mode == 3) {
                creature_pool[slot].freeware.force_target = 1;
                creature_pool[slot].freeware.target.x =
                    (float)cos(angle) * dist * .35f + PLAYER(creature_pool[slot].freeware.player).position.x;
                creature_pool[slot].freeware.target.y =
                    (float)sin(angle) * dist * .35f + PLAYER(creature_pool[slot].freeware.player).position.y;
            } else {
                if (PLAYER(0).perks[perk_id_almost_invisible] > 0)
                    angle += (1.f - ((float)sin(freeware_simulation_clock) * .35f + .5f) * .5f) * half_pi;
                creature_pool[slot].freeware.target.x =
                    (float)cos(angle) * dist * .85f + PLAYER(creature_pool[slot].freeware.player).position.x;
                creature_pool[slot].freeware.target.y =
                    (float)sin(angle) * dist * .85f + PLAYER(creature_pool[slot].freeware.player).position.y;
                if (!creature_pool[slot].freeware.force_target &&
                    range(creature_pool[slot].freeware.target, *position) < 15)
                    creature_pool[slot].freeware.force_target = 1;
            }

            creature_pool[slot].freeware.target_heading =
                (point(creature_pool[slot].freeware.target) - point(*position)).angle() + half_pi;
            if (creature_pool[slot].plague_infected)
                creature_pool[slot].freeware.target_heading += pi;
            angle_approach(&creature_pool[slot].freeware.heading,
                           creature_pool[slot].freeware.target_heading);
            vec2f_t *velocity = &creature_pool[slot].velocity;
            velocity->x = (float)(cos(creature_pool[slot].freeware.heading - half_pi) *
                                  creature_pool[slot].freeware.move_speed) *
                          frame_dt * 30.f;
            creature_pool[slot].vel_y = (float)(sin(creature_pool[slot].freeware.heading - half_pi) *
                                                creature_pool[slot].freeware.move_speed) *
                                        frame_dt * 30.f;
            freeware_current_map->move_with_collision(position, velocity, 8.f);
            plaguebearer_spread_infection(slot);

            creature_pool[slot].freeware.animation += frame_dt * creature_pool[slot].freeware.move_speed * 26;
            while (creature_pool[slot].freeware.animation > 31)
                creature_pool[slot].freeware.animation -= 31;
            creature_pool[slot].freeware.attack_cooldown -= frame_dt;
            if (creature_pool[slot].freeware.attack_cooldown < 0)
                creature_pool[slot].freeware.attack_cooldown = 0;
            {
                CreaturePoint offset = point(creature_pool[slot].position) -
                                       point(PLAYER(creature_pool[slot].freeware.player).position);
                float length = (float)sqrt(offset.x * offset.x + offset.y * offset.y);
                dist = length;
            }
            if (dist < 100 && PLAYER(current_player_index).perks[perk_id_radioactive] > 0) {
                phase_timer -= frame_dt * 1.5f;
                if (phase_timer < 0) {
                    phase_timer = .5f;
                    creature_pool[slot].health -= (100 - dist) * .3f;
                    creature_pool[slot].ai_mode = 1;
                    if (creature_pool[slot].health < 0) {
                        PLAYER(current_player_index).experience =
                            (int)(PLAYER(current_player_index).experience +
                                  creature_pool[slot].freeware.reward);
                        creature_pool[slot].death_timer -= frame_dt;
                    }
                    fx_queue_add_random(position);
                }
            }

            if (dist < 20) {
                position->x -= velocity->x;
                creature_pool[slot].pos_y -= creature_pool[slot].vel_y;
            }
            if (dist < 30) {
                if (FREEWARE_EDITION == 10300 || PLAYER(creature_pool[slot].freeware.player).health > 0) {
                    if (creature_pool[slot].freeware.attack_cooldown <= 0) {
                        sfx_play_panned(crt_rand() % 4 + 9, .45f, .5f);
                        if (freeware_berserk_timer < 12 &&
#if FREEWARE_EDITION == 10300
                            !PLAYER(current_player_index).perks[CONTACT_IMMUNITY] &&
#endif
                            PLAYER(current_player_index).shield <= 0) {
                            PLAYER(creature_pool[slot].freeware.player).health -=
                                creature_pool[slot].freeware.contact_damage;
                            CreaturePoint delta =
                                point(PLAYER(creature_pool[slot].freeware.player).position) -
                                point(creature_pool[slot].position);
                            float inverse_length = 1.f / (float)sqrt((delta.x * delta.x + delta.y * delta.y));
                            delta.x *= inverse_length;
                            delta.y *= inverse_length;
                            CreaturePoint mark =
                                point(PLAYER(creature_pool[slot].freeware.player).position) + delta * 3.f;
                            fx_queue_add_random((vec2f_t *)&mark);
                        }
                        creature_pool[slot].freeware.attack_cooldown += 1;
                    }
                    if (PLAYER(current_player_index).plaguebearer &&
                        (creature_pool[slot].health < 150 && plaguebearer_infection_count < 50))
                        creature_pool[slot].plague_infected = 1;
                }
                if (creature_pool[slot].freeware.size <= 30) {
                    creature_pool[slot].health = 0;
                    creature_pool[slot].death_timer -= frame_dt;
                }
            }
        } else {
            creature_pool[slot].death_timer -= frame_dt * 28;
            creature_pool[slot].vel_x = (float)cos(creature_pool[slot].freeware.heading - half_pi) *
                                        creature_pool[slot].death_timer * frame_dt * 9;
            creature_pool[slot].vel_y = (float)(sin(creature_pool[slot].freeware.heading - half_pi) *
                                                creature_pool[slot].death_timer) *
                                        frame_dt * 9;
            position->x -= creature_pool[slot].vel_x;
            creature_pool[slot].pos_y -= creature_pool[slot].vel_y;
        }
    }
}
#undef CONTACT_IMMUNITY
#endif
#undef PLAYER
