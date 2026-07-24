#include <math.h>

#include "crimsonland_gameplay.h"

struct survival_vec2_t {
    float x;
    float y;

    survival_vec2_t &operator+=(const survival_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

extern "C" unsigned char console_open_flag;
extern "C" unsigned char survival_reward_fire_seen;
extern "C" unsigned char survival_reward_handout_enabled;
extern "C" int config_player_count;
extern "C" int frame_dt_ms;
extern "C" int survival_reward_weapon_guard_id;
extern "C" int survival_recent_death_count;
extern "C" int survival_spawn_cooldown;
extern "C" int quest_spawn_timeline;
extern "C" int demo_time_limit_ms;
extern "C" survival_vec2_t survival_recent_death_pos[3];

extern "C" void survival_spawn_creature(float *pos);
extern "C" void demo_mode_start(void);

extern "C" void survival_update(void)
{
    if (console_open_flag) {
        return;
    }

    quest_spawn_timeline += frame_dt_ms;
    if (demo_mode_active) {
        if (quest_spawn_timeline > demo_time_limit_ms) {
            render_pass_mode = 0;
            demo_mode_start();
        }
        return;
    }

    {
        if (config_player_count == 1) {
        if (!survival_reward_damage_seen
            && !survival_reward_fire_seen
            && survival_elapsed_ms > 64000
            && survival_reward_handout_enabled) {
            if (player_state_table[0].weapon_id == WEAPON_ID_PISTOL) {
                weapon_assign_player(0, WEAPON_ID_SHRINKIFIER_5K);
                survival_reward_weapon_guard_id = WEAPON_ID_SHRINKIFIER_5K;
            }
            survival_reward_handout_enabled = 0;
            survival_reward_damage_seen = 1;
            survival_reward_fire_seen = 1;
        }

        if (survival_recent_death_count == 3
            && !survival_reward_fire_seen) {
            survival_vec2_t pos;
            pos.x = survival_recent_death_pos[0].x;
            pos.y = survival_recent_death_pos[0].y;
            pos += survival_recent_death_pos[1];
            pos += survival_recent_death_pos[2];
            pos.x *= 0.333333343f;
            pos.y *= 0.333333343f;
            float dx = player_state_table[0].pos_x - pos.x;
            float dy = player_state_table[0].pos_y - pos.y;
            if ((float)sqrt(dx * dx + dy * dy) < 16.0f
                && player_state_table[0].health < 15.0f) {
                weapon_assign_player(0, WEAPON_ID_BLADE_GUN);
                survival_reward_weapon_guard_id = WEAPON_ID_BLADE_GUN;
                survival_reward_fire_seen = 1;
                survival_reward_handout_enabled = 0;
            }
        }
        }

        survival_vec2_t pos;
        if (survival_spawn_stage == 0) {
        if (player_state_table[0].level <= 4) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 1;
        pos.x = -164.0f;
        pos.y = 512.0f;
        creature_spawn_template(
            SPAWN_ID_FORMATION_RING_ALIEN_8_12,
            (const vec2f_t *)&pos,
            3.14159274f
        );
        pos.x = 1188.0f;
        pos.y = 512.0f;
        creature_spawn_template(
            SPAWN_ID_FORMATION_RING_ALIEN_8_12,
            (const vec2f_t *)&pos,
            3.14159274f
        );
        }

        if (survival_spawn_stage == 1) {
        if (player_state_table[0].level <= 8) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 2;
        pos.x = 1088.0f;
        pos.y = 512.0f;
        creature_spawn_template(
            SPAWN_ID_ALIEN_CONST_RED_BOSS_2C,
            (const vec2f_t *)&pos,
            3.14159274f
        );
        }
    }

    if (survival_spawn_stage == 2) {
        if (player_state_table[0].level <= 10) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 3;
        vec2f_t pos;
        for (int i0 = 0; i0 < 12; ++i0) {
            pos.x = 1088.0f;
            pos.y = (float)i0 * 42.6666679f + 256.0f;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP2_RANDOM_35,
                &pos,
                3.14159274f
            );
        }
    }

    if (survival_spawn_stage == 3) {
        if (player_state_table[0].level <= 12) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 4;
        vec2f_t pos;
        for (int i1 = 0; i1 < 4; ++i1) {
            pos.x = 1088.0f;
            pos.y = (float)i1 * 64.0f + 384.0f;
            creature_spawn_template(
                SPAWN_ID_ALIEN_CONST_RED_FAST_2B,
                &pos,
                3.14159274f
            );
        }
    }

    if (survival_spawn_stage == 4) {
        if (player_state_table[0].level <= 14) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 5;
        vec2f_t pos;
        for (int i2 = 0; i2 < 4; ++i2) {
            pos.x = 1088.0f;
            pos.y = (float)i2 * 64.0f + 384.0f;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
                &pos,
                3.14159274f
            );
        }
        for (int i3 = 0; i3 < 4; ++i3) {
            pos.x = -64.0f;
            pos.y = (float)i3 * 64.0f + 384.0f;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
                &pos,
                3.14159274f
            );
        }
    }

    if (survival_spawn_stage == 5) {
        if (player_state_table[0].level <= 16) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 6;
        vec2f_t pos;
        pos.x = 1088.0f;
        pos.y = 512.0f;
        creature_spawn_template(
            SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
            &pos,
            3.14159274f
        );
    }

    if (survival_spawn_stage == 6) {
        if (player_state_table[0].level <= 18) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 7;
        vec2f_t pos;
        pos.x = 640.0f;
        pos.y = 512.0f;
        creature_spawn_template(
            SPAWN_ID_SPIDER_SP2_SPLITTER_01,
            &pos,
            3.14159274f
        );
    }

    if (survival_spawn_stage == 7) {
        if (player_state_table[0].level <= 20) {
            goto update_wave_spawns;
        }
        survival_spawn_stage = 8;
        vec2f_t pos;
        pos.x = 384.0f;
        pos.y = 256.0f;
        creature_spawn_template(
            SPAWN_ID_SPIDER_SP2_SPLITTER_01,
            &pos,
            3.14159274f
        );
        pos.x = 640.0f;
        pos.y = 768.0f;
        creature_spawn_template(
            SPAWN_ID_SPIDER_SP2_SPLITTER_01,
            &pos,
            3.14159274f
        );
    }

    if (survival_spawn_stage == 8
        && player_state_table[0].level > 25) {
        survival_spawn_stage = 9;
        vec2f_t pos;
        for (int i4 = 0; i4 < 4; ++i4) {
            pos.x = 1088.0f;
            pos.y = (float)i4 * 64.0f + 384.0f;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                &pos,
                3.14159274f
            );
        }
        for (int i5 = 0; i5 < 4; ++i5) {
            pos.x = -64.0f;
            pos.y = (float)i5 * 64.0f + 384.0f;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                &pos,
                3.14159274f
            );
        }
    }

    if (survival_spawn_stage == 9
        && player_state_table[0].level > 31) {
        survival_spawn_stage = 10;
        vec2f_t pos;
        pos.x = 1088.0f;
        pos.y = 512.0f;
        creature_spawn_template(
            SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
            &pos,
            3.14159274f
        );
        pos.x = -64.0f;
        pos.y = 512.0f;
        creature_spawn_template(
            SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
            &pos,
            3.14159274f
        );
        for (int i6 = 0; i6 < 4; ++i6) {
            pos.x = (float)i6 * 64.0f + 384.0f;
            pos.y = -64.0f;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                &pos,
                3.14159274f
            );
        }
        for (int i7 = 0; i7 < 4; ++i7) {
            pos.x = (float)i7 * 64.0f + 384.0f;
            pos.y = 1088.0f;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                &pos,
                3.14159274f
            );
        }
    }

update_wave_spawns:
    survival_spawn_cooldown -= frame_dt_ms * config_player_count;
    render_overlay_player_index = 0;
    while (survival_spawn_cooldown < 0) {
        int interval = 500 - survival_elapsed_ms / 1800;
        if (interval < 0) {
            unsigned int extra_count = (unsigned int)(1 - interval) >> 1;
            interval += (int)extra_count * 2;
            do {
                switch (crt_rand() & 3) {
                    case 0: {
                        vec2f_t top;
                        int width = terrain_texture_width;
                        int roll = crt_rand();
                        top.x = (float)(roll % width);
                        top.y = -40.0f;
                        survival_spawn_creature(&top.x);
                        break;
                    }
                    case 1: {
                        vec2f_t bottom;
                        int width = terrain_texture_width;
                        int roll = crt_rand();
                        bottom.x = (float)(roll % width);
                        bottom.y = (float)terrain_texture_height + 40.0f;
                        survival_spawn_creature(&bottom.x);
                        break;
                    }
                    case 2: {
                        vec2f_t left;
                        int height = terrain_texture_height;
                        int roll = crt_rand();
                        left.x = -40.0f;
                        left.y = (float)(roll % height);
                        survival_spawn_creature(&left.x);
                        break;
                    }
                    case 3: {
                        vec2f_t right;
                        int height = terrain_texture_height;
                        int roll = crt_rand();
                        float y = (float)(roll % height);
                        right.x = (float)terrain_texture_width + 40.0f;
                        right.y = y;
                        survival_spawn_creature(&right.x);
                        break;
                    }
                }
                --extra_count;
            } while (extra_count != 0);
        }

        if (interval < 1) {
            interval = 1;
        }
        survival_spawn_cooldown += interval;

        switch (crt_rand() & 3) {
            case 0: {
                vec2f_t top;
                int width = terrain_texture_width;
                int roll = crt_rand();
                top.x = (float)(roll % width);
                top.y = -40.0f;
                survival_spawn_creature(&top.x);
                break;
            }
            case 1: {
                vec2f_t bottom;
                int width = terrain_texture_width;
                int roll = crt_rand();
                bottom.x = (float)(roll % width);
                bottom.y = (float)terrain_texture_height + 40.0f;
                survival_spawn_creature(&bottom.x);
                break;
            }
            case 2: {
                vec2f_t left;
                int height = terrain_texture_height;
                int roll = crt_rand();
                left.x = -40.0f;
                left.y = (float)(roll % height);
                survival_spawn_creature(&left.x);
                break;
            }
            case 3: {
                vec2f_t right;
                int height = terrain_texture_height;
                int roll = crt_rand();
                float y = (float)(roll % height);
                right.x = (float)terrain_texture_width + 40.0f;
                right.y = y;
                survival_spawn_creature(&right.x);
                break;
            }
        }
    }
}
