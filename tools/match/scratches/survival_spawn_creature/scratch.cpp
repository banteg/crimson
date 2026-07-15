#include "crimsonland_gameplay.h"

struct survival_vec2_t {
    float x;
    float y;

    survival_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct survival_color_t {
    float r;
    float g;
    float b;
    float a;

    survival_color_t(float red, float green, float blue, float alpha)
        : r(red), g(green), b(blue), a(alpha) {}
};

struct survival_creature_t {
    unsigned char active;
    unsigned char _pad0[3];
    int phase_seed;
    unsigned char state_flag;
    unsigned char collision_flag;
    unsigned char _pad1[2];
    float collision_timer;
    float lifecycle_stage;
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    float health;
    float max_health;
    float heading;
    float target_heading;
    float size;
    float hit_flash_timer;
    survival_color_t tint;
    unsigned char force_target;
    unsigned char _pad_force_target[3];
    float target_x;
    float target_y;
    float contact_damage;
    float move_speed;
    float attack_cooldown;
    float reward_value;
    unsigned char _pad2[4];
    int type_id;
    int target_player;
    unsigned char _pad3[4];
    int link_index;
    float target_offset_x;
    float target_offset_y;
    float orbit_angle;
    unsigned int orbit_radius;
    int flags;
    int ai_mode;
    float anim_phase;
};

extern "C" void survival_spawn_creature(float *pos)
{
    survival_creature_t *creature =
        (survival_creature_t *)&creature_pool[creature_alloc_slot()];

    creature->pos_x = pos[0];
    creature->pos_y = pos[1];
    creature->collision_flag = 0;
    creature->collision_timer = 0.0f;
    creature->ai_mode = 0;

    int type_roll = crt_rand() % 10;
    if (player_state_table[0].experience < 12000) {
        if (type_roll <= 8) {
            creature->type_id = 2;
        } else {
            creature->type_id = 3;
        }
    } else if (player_state_table[0].experience < 25000) {
        if (type_roll <= 3) {
            creature->type_id = 0;
        } else {
            creature->type_id = 3;
        }
        if (type_roll >= 9) {
            creature->type_id = 2;
        }
    } else if (player_state_table[0].experience < 42000) {
        if (type_roll <= 4) {
            creature->type_id = 2;
        } else {
            creature->type_id = crt_rand() % 2 + 3;
        }
    } else if (player_state_table[0].experience < 50000) {
        creature->type_id = 2;
    } else if (player_state_table[0].experience < 90000) {
        creature->type_id = 4;
    } else if (player_state_table[0].experience < 110000) {
        creature->type_id = 0;
    } else if (type_roll <= 5) {
        creature->type_id = 2;
    } else if (type_roll <= 8) {
        creature->type_id = 4;
    } else {
        creature->type_id = 0;
    }

    if ((crt_rand() & 0x1f) == 2) {
        creature->type_id = 3;
    }

    int size_roll = crt_rand();
    creature->active = 1;
    creature->force_target = 0;
    creature->lifecycle_stage = 16.0f;
    creature->size = (float)(size_roll % 20 + 44);
    *(survival_vec2_t *)&creature->vel_x = survival_vec2_t(0.0f, 0.0f);
    creature->heading = (float)(crt_rand() % 314) * 0.01f;
    creature->move_speed =
        (float)(player_state_table[0].experience / 4000) * 0.045f + 0.9f;

    if (creature->type_id == 3) {
        creature->flags |= 0x80;
        creature->move_speed *= 1.3f;
    }

    creature->health =
        (float)(crt_rand() & 0xf)
        + (float)player_state_table[0].experience * 0.00125f
        + 52.0f;

    if (creature->type_id == 0) {
        creature->move_speed *= 0.6f;
        if (creature->move_speed < 1.3f) {
            creature->move_speed = 1.3f;
        }
        creature->health *= 1.5f;
    }
    if (creature->move_speed > 3.5f) {
        creature->move_speed = 3.5f;
    }

    creature->attack_cooldown = 0.0f;
    creature->reward_value = 0.0f;

    if (player_state_table[0].experience < 50000) {
        creature->tint.r =
            1.0f
            - 1.0f / ((float)(player_state_table[0].experience / 1000) + 10.0f);
        creature->tint.g =
            (float)(crt_rand() % 10) * 0.01f
            + 0.9f
            - 1.0f / ((float)(player_state_table[0].experience / 10000) + 10.0f);
        creature->tint.b = (float)(crt_rand() % 10) * 0.01f + 0.7f;
    } else {
        if (player_state_table[0].experience < 100000) {
            creature->tint.r =
                0.9f
                - 1.0f
                    / ((float)(player_state_table[0].experience / 1000) + 10.0f);
            creature->tint.g =
                (float)(crt_rand() % 10) * 0.01f
                + 0.8f
                - 1.0f
                    / ((float)(player_state_table[0].experience / 10000) + 10.0f);
            creature->tint.b =
                (float)(crt_rand() % 10) * 0.01f
                + (float)(player_state_table[0].experience - 50000) * 0.000006f
                + 0.7f;
        } else {
            creature->tint.r =
                1.0f
                - 1.0f
                    / ((float)(player_state_table[0].experience / 1000) + 10.0f);
            creature->tint.g =
                (float)(crt_rand() % 10) * 0.01f
                + 0.9f
                - 1.0f
                    / ((float)(player_state_table[0].experience / 10000) + 10.0f);
            creature->tint.b =
                (float)(crt_rand() % 10) * 0.01f
                + 1.0f
                - (float)(player_state_table[0].experience - 100000) * 0.000003f;
            if (creature->tint.b < 0.5f) {
                creature->tint.b = 0.5f;
            }
        }
    }

    creature->tint.a = 1.0f;
    creature->contact_damage = creature->size * 0.0952381f;
    if (creature->reward_value == 0.0f) {
        creature->reward_value =
            (float)(crt_rand() % 10 + 10)
            + creature->move_speed * 5.0f
            + creature->contact_damage * 0.8f
            + creature->health * 0.4f;
    }

    if (crt_rand() % 180 < 2) {
        creature->tint = survival_color_t(0.9f, 0.4f, 0.4f, 1.0f);
        creature->health = 65.0f;
        creature->reward_value = 320.0f;
    } else if (crt_rand() % 240 < 2) {
        creature->tint = survival_color_t(0.4f, 0.9f, 0.4f, 1.0f);
        creature->health = 85.0f;
        creature->reward_value = 420.0f;
    } else if (crt_rand() % 360 < 2) {
        creature->tint = survival_color_t(0.4f, 0.4f, 0.9f, 1.0f);
        creature->health = 125.0f;
        creature->reward_value = 520.0f;
    }

    if (crt_rand() % 1320 < 4) {
        creature->health += 230.0f;
        creature->tint = survival_color_t(0.84f, 0.24f, 0.89f, 1.0f);
        creature->size = 80.0f;
        creature->reward_value = 600.0f;
    } else if (crt_rand() % 1620 < 4) {
        creature->health += 2230.0f;
        creature->tint = survival_color_t(0.94f, 0.84f, 0.29f, 1.0f);
        creature->size = 85.0f;
        creature->reward_value = 900.0f;
    }

    creature->state_flag = 1;
    creature->max_health = creature->health;
    creature->reward_value *= 0.8f;

    survival_color_t *color = &creature->tint;
    if (color->r < 0.0f) {
        color->r = 0.0f;
    } else if (color->r > 1.0f) {
        color->r = 1.0f;
    }
    if (color->g < 0.0f) {
        color->g = 0.0f;
    } else if (color->g > 1.0f) {
        color->g = 1.0f;
    }
    if (color->b < 0.0f) {
        color->b = 0.0f;
    } else if (color->b > 1.0f) {
        color->b = 1.0f;
    }
    if (color->a < 0.0f) {
        color->a = 0.0f;
    } else if (color->a > 1.0f) {
        color->a = 1.0f;
    }
}
