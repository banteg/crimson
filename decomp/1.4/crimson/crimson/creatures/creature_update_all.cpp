#include "freeware_edition.h"
// 0x40d8c0. Corpse retirement is a separate pass inside creature rendering (0x40fd10).
#include "freeware_level.h"
#include <math.h>
extern "C" {
extern creature_t creature_pool[CL_BUILD == 10002 ? 128 : 512];
#if CL_BUILD < 10400
extern freeware_player_t player_state_table[2];
#define PLAYER(i) player_state_table[i]
#else
extern player_state_t player_state_table[2];
#define PLAYER(i) player_state_table[i].freeware
#endif
extern float frame_dt, bonus_freeze_timer, freeware_simulation_clock, freeware_berserk_timer;
extern int plaguebearer_infection_count, current_player_index;
extern game_mode_id_t config_game_mode;
extern unsigned char freeware_game_active;
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
#if CL_BUILD == 10300
float angle_approach(float *, float);
#else
float angle_approach(float *, float, float);
#endif
int plaguebearer_spread_infection(int);
int crt_rand();
#if CL_BUILD == 10300
void creature_handle_death(int, int);
#else
void creature_handle_death(int, int, unsigned char);
#endif
void fx_queue_add_random(const vec2f_t *);
#if CL_BUILD < 10400
int sfx_play_panned(int, float, float);
#define attack_sound(id) sfx_play_panned(id, .45f, .5f)
extern int perk_id_almost_invisible, perk_id_radioactive, perk_id_reserved_22;
#define PERK_ID(name) perk_id_##name
#define CONTACT_IMMUNITY perk_id_reserved_22
#else
void freeware_combat_sound(int, float);
#define attack_sound(id) freeware_combat_sound(id, .45f)
#define PERK_ID(name) freeware_rules::name
#define CONTACT_IMMUNITY 22
#endif
}
#if FREEWARE_EDITION == 10002
#define TARGET_PLAYER PLAYER(current_player_index)
#else
#define TARGET_PLAYER PLAYER(c.freeware.player)
#endif
#ifndef _MSC_VER
#define __forceinline inline
#endif
namespace creature_update140 {
const float pi = 3.14159274f, half_pi = 1.57079637f;
static __forceinline float range(const vec2f_t &a, const vec2f_t &b) {
    float x = a.x - b.x, y = a.y - b.y;
    return (float)sqrt(x * x + y * y);
}
} // namespace creature_update140
extern "C" void creature_update_all() {
    using namespace creature_update140;
    if (bonus_freeze_timer > 0)
        return;
    for (int i = 0; i < (FREEWARE_EDITION == 10002 ? 128 : 512); ++i) {
        creature_t &c = creature_pool[i];
        if (!c.active)
            continue;
#if FREEWARE_EDITION != 10002
        if (c.health <= 0 && c.death_timer == 16)
            c.death_timer -= frame_dt;
        float dist = range(TARGET_PLAYER.position, c.position);
#if FREEWARE_EDITION == 10300
        if (config_game_mode == 3) {
#else
        if (config_game_mode != 2) {
#endif
            if (dist < c.activation_radius)
                c.ai_mode = 1;
            if (!c.ai_mode)
                continue;
        }
        if (c.hit_flash_timer != -1) {
            c.hit_flash_timer += frame_dt;
            if (c.hit_flash_timer > 4) {
                if (FREEWARE_EDITION == 10300 || freeware_game_active) {
                    effect_color_t color = {.8f, .8f, .8f, 1};
                    int child = creature_spawn(&c.position, &color, 1);
                    if (child != -1) {
                        creature_pool[child].freeware.size = 30;
                        creature_pool[child].freeware.move_speed *= .6f;
                    }
                }
                c.hit_flash_timer -= 4;
            }
        }
        if (c.hit_flash_timer > 2.5f)
            continue;
        if (TARGET_PLAYER.health <= 0)
            c.freeware.player = 1 - c.freeware.player;
#endif
        if (c.death_timer == 16) {
#if CL_BUILD == 10002
            float &phase_timer = c.plague_timer;
#else
            float &phase_timer = c.anim_phase;
#endif
            if (c.plague_infected) {
                phase_timer -= frame_dt;
                if (phase_timer < 0) {
                    if (FREEWARE_EDITION == 10002)
                        phase_timer = .5f;
                    else
                        phase_timer += .5f;
                    c.health -= FREEWARE_EDITION == 10002 ? 5 : 15;
#if FREEWARE_EDITION != 10002
                    c.ai_mode = 1;
#endif
                    if (c.health < 0) {
#if FREEWARE_EDITION == 10002
                        PLAYER(current_player_index).experience += (int)c.freeware.reward;
                        c.death_timer -= frame_dt;
#else
                        ++plaguebearer_infection_count;
#if CL_BUILD == 10300
                        creature_handle_death(i, current_player_index);
#else
                        creature_handle_death(i, current_player_index, 1);
#endif
#if FREEWARE_EDITION >= 10400
                        freeware_combat_sound(28, (crt_rand() % 70) * .1f + .3f);
#endif
#endif
                    }
                    fx_queue_add_random(&c.position);
                }
            }

#if FREEWARE_EDITION < 10400
            float angle = i * 3.7f * pi;
#else
            double angle = i * (double)3.7f * pi;
#endif
            float offset_scale = .85f;
            c.freeware.force_target = 0;
#if FREEWARE_EDITION == 10002
            float dist = range(TARGET_PLAYER.position, c.position);
#else
            if (config_game_mode == 3) {
                offset_scale = .35f;
                c.freeware.force_target = 1;
            } else if (PLAYER(0).perks[PERK_ID(almost_invisible)] > 0)
                angle += (1 - (sin(freeware_simulation_clock) * .35f + .5f) * .5f) * half_pi;
#endif
            c.freeware.target.x = TARGET_PLAYER.position.x + (float)cos(angle) * dist * offset_scale;
            c.freeware.target.y = TARGET_PLAYER.position.y + (float)sin(angle) * dist * offset_scale;
            if (range(c.freeware.target, c.position) < 15)
                c.freeware.force_target = 1;
            double heading =
                atan2((double)c.freeware.target.y - c.pos_y, (double)c.freeware.target.x - c.pos_x) + half_pi;
#if FREEWARE_EDITION == 10002
            c.freeware.heading = (float)heading;
#else
            c.freeware.target_heading = (float)(heading + (c.plague_infected ? pi : 0));
#if CL_BUILD == 10300
            angle_approach(&c.freeware.heading, c.freeware.target_heading);
#else
            angle_approach(&c.freeware.heading, c.freeware.target_heading, 0);
#endif
#endif
            c.vel_x = (float)cos(c.freeware.heading - half_pi) * c.freeware.move_speed * frame_dt * 30;
            c.vel_y = (float)sin(c.freeware.heading - half_pi) * c.freeware.move_speed * frame_dt * 30;
#if FREEWARE_EDITION == 10300
            freeware_current_map->move_with_collision(&c.position, &c.velocity, 8.f);
#else
            c.pos_x += c.vel_x;
            c.pos_y += c.vel_y;
#endif
#if FREEWARE_EDITION == 10002
            // The early creatures also drift with their attack timer, even at zero pursuit speed.
            float phase = c.freeware.attack_cooldown * 12.566371f;
            c.pos_x += (float)cos(phase) * frame_dt * 10;
            c.pos_y += (float)sin(phase) * frame_dt * 10;
            int other = plaguebearer_spread_infection(i);
            if (other) {
                creature_t &peer = creature_pool[other];
                peer.pos_x -= c.vel_x;
                peer.pos_y -= c.vel_y;
                c.pos_x += peer.vel_x;
                c.pos_y += peer.vel_y;
            }
#else
            plaguebearer_spread_infection(i);
#endif
            c.freeware.animation += frame_dt * c.freeware.move_speed * 26;
            while (c.freeware.animation > 31)
                c.freeware.animation -= 31;
            c.freeware.attack_cooldown -= frame_dt;
            if (c.freeware.attack_cooldown < 0)
                c.freeware.attack_cooldown = 0;
            dist = range(c.position, TARGET_PLAYER.position);
            if (dist < 100 && PLAYER(current_player_index).perks[PERK_ID(radioactive)] > 0) {
                phase_timer -= frame_dt * 1.5f;
                if (phase_timer < 0) {
                    phase_timer = .5f;
                    c.health -= (100 - dist) * .3f;
#if FREEWARE_EDITION != 10002
                    c.ai_mode = 1;
#endif
                    if (c.health < 0) {
                        PLAYER(current_player_index).experience = (int)(PLAYER(current_player_index).experience + c.freeware.reward);
                        c.death_timer -= frame_dt;
                    }
                    fx_queue_add_random(&c.position);
                }
            }
            if (dist < 20) {
                c.pos_x -= c.vel_x;
                c.pos_y -= c.vel_y;
            }
            if (dist >= 30)
                continue;
            if (FREEWARE_EDITION < 10400 || TARGET_PLAYER.health > 0) {
                if (c.freeware.attack_cooldown <= 0) {
                    attack_sound(crt_rand() % 4 + 9);
#if FREEWARE_EDITION == 10002
                    bool hurt = freeware_berserk_timer >= 0;
#elif FREEWARE_EDITION == 10300
                    bool hurt = freeware_berserk_timer < 12 && !PLAYER(current_player_index).perks[CONTACT_IMMUNITY] &&
                                PLAYER(current_player_index).shield <= 0;
#else
                    bool hurt = freeware_berserk_timer < 12 && PLAYER(current_player_index).shield <= 0;
#endif
                    if (hurt)
                        TARGET_PLAYER.health -= c.freeware.contact_damage;
                    if (FREEWARE_EDITION == 10002 || hurt) {
                        vec2f_t mark = TARGET_PLAYER.position;
                        float dx = TARGET_PLAYER.position.x - c.pos_x, dy = TARGET_PLAYER.position.y - c.pos_y;
                        float length = (float)sqrt(dx * dx + dy * dy);
                        if (FREEWARE_EDITION < 10400 || length > 0) {
                            float inverse_length = 1 / length;
                            mark.x += dx * inverse_length * 3;
                            mark.y += dy * inverse_length * 3;
                        }
                        fx_queue_add_random(&mark);
                    }
                    c.freeware.attack_cooldown += 1;
                }
                if (PLAYER(current_player_index).plaguebearer &&
                    (FREEWARE_EDITION == 10002 || (c.health < 150 && plaguebearer_infection_count < 50)))
                    c.plague_infected = 1;
            }
            if (FREEWARE_EDITION != 10002 && c.freeware.size <= 30) {
                c.health = 0;
                c.death_timer -= frame_dt;
            }
        } else {
            c.death_timer -= frame_dt * 28;
            c.vel_x = (float)cos(c.freeware.heading - half_pi) * c.death_timer * frame_dt * 9;
            c.vel_y = (float)sin(c.freeware.heading - half_pi) * c.death_timer * frame_dt * 9;
            c.pos_x -= c.vel_x;
            c.pos_y -= c.vel_y;
        }
    }
}
