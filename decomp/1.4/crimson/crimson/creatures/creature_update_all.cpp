// 0x40d8c0. Corpse retirement is a separate pass inside creature rendering (0x40fd10).
#include "crimsonland_types.h"
#include <math.h>
extern "C" {
extern creature_t creature_pool[512];
extern player_state_t player_state_table[2];
extern float frame_dt, bonus_freeze_timer, freeware_simulation_clock, freeware_berserk_timer;
extern int plaguebearer_infection_count, current_player_index;
extern game_mode_id_t config_game_mode;
extern unsigned char freeware_game_active;
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
float angle_approach(float *, float, float);
int plaguebearer_spread_infection(int);
int crt_rand();
void creature_handle_death(int, int, unsigned char);
void fx_queue_add_random(const vec2f_t *);
void freeware_combat_sound(int, float);
}
namespace creature_update140 {
const float pi = 3.14159274f, half_pi = 1.57079637f;
float range(vec2f_t a, vec2f_t b) {
    float x = a.x - b.x, y = a.y - b.y;
    return (float)sqrt((double)x * x + (double)y * y);
}
} // namespace creature_update140
extern "C" void creature_update_all() {
    using namespace creature_update140;
    if (bonus_freeze_timer > 0)
        return;
    for (int i = 0; i < 512; ++i) {
        creature_t &c = creature_pool[i];
        if (!c.active)
            continue;
        if (c.health <= 0 && c.death_timer == 16)
            c.death_timer -= frame_dt;
        int target = c.freeware.player;
        float dist = range(c.position, player_state_table[target].freeware.position);
        if (config_game_mode != 2) {
            if (dist < c.activation_radius)
                c.ai_mode = 1;
            if (!c.ai_mode)
                continue;
        }
        if (c.hit_flash_timer != -1) {
            c.hit_flash_timer += frame_dt;
            if (c.hit_flash_timer > 4) {
                if (freeware_game_active) {
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
        if (player_state_table[target].freeware.health <= 0)
            c.freeware.player = target = 1 - target;
        if (c.death_timer != 16) {
            c.death_timer -= frame_dt * 28;
            c.vel_x = (float)(cos((double)c.freeware.heading - half_pi) * c.death_timer * frame_dt * 9);
            c.vel_y = (float)(sin((double)c.freeware.heading - half_pi) * c.death_timer * frame_dt * 9);
            c.pos_x -= c.vel_x;
            c.pos_y -= c.vel_y;
            continue;
        }
        if (c.plague_infected) {
            c.anim_phase -= frame_dt;
            if (c.anim_phase < 0) {
                c.anim_phase += .5f;
                c.health -= 15;
                c.ai_mode = 1;
                if (c.health < 0) {
                    ++plaguebearer_infection_count;
                    creature_handle_death(i, current_player_index, 1);
                    freeware_combat_sound(28, (crt_rand() % 70) * .1f + .3f);
                }
                fx_queue_add_random(&c.position);
            }
        }
        freeware_player_t &p = player_state_table[target].freeware;
        freeware_player_t &current = player_state_table[current_player_index].freeware;
        double angle = i * (double)3.7f * pi;
        float offset_scale = .85f;
        c.freeware.force_target = 0;
        if (config_game_mode == 3) {
            offset_scale = .35f;
            c.freeware.force_target = 1;
        } else if (player_state_table[0].freeware.perks[2])
            angle += (1 - (sin(freeware_simulation_clock) * .35f + .5f) * .5f) * half_pi;
        c.freeware.target.x = (float)(p.position.x + cos(angle) * dist * offset_scale);
        c.freeware.target.y = (float)(p.position.y + sin(angle) * dist * offset_scale);
        if (range(c.freeware.target, c.position) < 15)
            c.freeware.force_target = 1;
        double heading =
            atan2((double)c.freeware.target.y - c.pos_y, (double)c.freeware.target.x - c.pos_x) + half_pi;
        c.freeware.target_heading = (float)(heading + (c.plague_infected ? pi : 0));
        angle_approach(&c.freeware.heading, c.freeware.target_heading, 0);
        c.vel_x = (float)(cos((double)c.freeware.heading - half_pi) * c.freeware.move_speed * frame_dt * 30);
        c.vel_y = (float)(sin((double)c.freeware.heading - half_pi) * c.freeware.move_speed * frame_dt * 30);
        c.pos_x += c.vel_x;
        c.pos_y += c.vel_y;
        plaguebearer_spread_infection(i);
        c.freeware.animation += frame_dt * c.freeware.move_speed * 26;
        while (c.freeware.animation > 31)
            c.freeware.animation -= 31;
        c.freeware.attack_cooldown -= frame_dt;
        if (c.freeware.attack_cooldown < 0)
            c.freeware.attack_cooldown = 0;
        dist = range(c.position, p.position);
        if (dist < 100 && current.perks[12] > 0) {
            c.anim_phase -= frame_dt * 1.5f;
            if (c.anim_phase < 0) {
                c.anim_phase = .5f;
                c.health -= (100 - dist) * .3f;
                c.ai_mode = 1;
                if (c.health < 0) {
                    current.experience = (int)(current.experience + c.freeware.reward);
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
        if (p.health > 0) {
            if (c.freeware.attack_cooldown <= 0) {
                freeware_combat_sound(crt_rand() % 4 + 9, .45f);
                if (freeware_berserk_timer < 12 && current.shield <= 0) {
                    p.health -= c.freeware.contact_damage;
                    vec2f_t mark = p.position;
                    float dx = p.position.x - c.pos_x, dy = p.position.y - c.pos_y;
                    float length = (float)sqrt((double)dx * dx + (double)dy * dy);
                    if (length > 0) {
                        mark.x += dx / length * 3;
                        mark.y += dy / length * 3;
                    }
                    fx_queue_add_random(&mark);
                }
                c.freeware.attack_cooldown += 1;
            }
            if (current.plaguebearer && c.health < 150 && plaguebearer_infection_count < 50)
                c.plague_infected = 1;
        }
        if (c.freeware.size <= 30) {
            c.health = 0;
            c.death_timer -= frame_dt;
        }
    }
}
