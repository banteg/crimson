#include <string.h>

struct reset_vec2_t {
    float x;
    float y;

    reset_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    reset_vec2_t &operator+=(const reset_vec2_t &other) {
        x += other.x;
        y += other.y;
        return *this;
    }

    reset_vec2_t &operator-=(const reset_vec2_t &other) {
        x -= other.x;
        y -= other.y;
        return *this;
    }
};

#include "crimsonland_gameplay.h"

struct reset_player_state_t {
    unsigned char reserved_00[9];
    unsigned char plaguebearer_active;
    unsigned char reserved_0a[0x0a];
    reset_vec2_t position;
    unsigned char reserved_1c[8];
    float health;
    unsigned char reserved_28[0x2e0];
    int state_aux;
    unsigned char reserved_30c[8];
    float speed_bonus_timer;
    float shield_timer;
    unsigned char reserved_31c[0x44];
};

#define reset_player_table ((reset_player_state_t *)player_state_table)

void player_reset_all(void)
{
    if (cv_verbose->value != 0.0f) {
        console_printf(&console_log_queue, "- Reseting players.\n");
    }

    render_overlay_player_index = 0;
    do {
        reset_vec2_t center(
            (float)terrain_texture_width * 0.5f,
            (float)terrain_texture_height * 0.5f);

        player_reset_reserved_zero = 0.0f;
        reset_player_table[render_overlay_player_index].speed_bonus_timer = 0.0f;
        reset_player_table[render_overlay_player_index].shield_timer = 0.0f;
        reset_player_table[render_overlay_player_index].state_aux = 0;
        reset_player_table[render_overlay_player_index].plaguebearer_active = 0;
        reset_player_table[render_overlay_player_index].position = center;
        reset_player_table[render_overlay_player_index].health = 100.0f;

        if (render_overlay_player_index % 2 == 0) {
            reset_vec2_t offset(
                (float)(render_overlay_player_index * 0x50),
                (float)(render_overlay_player_index * 0x50));
            reset_player_table[render_overlay_player_index].position += offset;
        } else {
            reset_vec2_t offset(
                (float)(render_overlay_player_index * 0x50),
                (float)(render_overlay_player_index * 0x50));
            reset_player_table[render_overlay_player_index].position -= offset;
        }

        {
            int reset_index = render_overlay_player_index;
            int alt_reload_time;

            player_state_table[reset_index].size = 48.0f;
            player_state_table[reset_index].speed_multiplier = 2.0f;
            player_state_table[reset_index].level = 1;
            player_state_table[reset_index].heading = 0.0f;
            player_state_table[reset_index].experience = 0;
            player_state_table[reset_index].reset_reserved_b0 = 0;
            player_state_table[reset_index].spread_heat = 0.0f;
            player_state_table[reset_index].move_speed = 0.0f;
            player_state_table[reset_index].ammo = 10.0f;
            player_state_table[reset_index].clip_size = 10.0f;
            player_state_table[reset_index].reload_timer_max = 1.0f;
            player_state_table[reset_index].reload_timer = 0.0f;
            player_state_table[reset_index].alt_weapon_id = 1;
            player_state_table[reset_index].alt_clip_size = (float)weapon_table[1].clip_size;
            player_state_table[reset_index].alt_reload_active = 0;
            player_state_table[reset_index].alt_ammo = player_state_table[reset_index].alt_clip_size;
            alt_reload_time = *(int *)&weapon_table[1].reload_time;
            player_state_table[reset_index].alt_reload_timer = 0.0f;
            player_state_table[reset_index].alt_shot_cooldown = 0.0f;
            *(int *)&player_state_table[reset_index].alt_reload_timer_max = alt_reload_time;
            player_state_table[reset_index].shot_cooldown = 0.8f;
            player_state_table[reset_index].weapon_id = 1;
            player_state_table[reset_index].reset_reserved_zero = 0;
            player_state_table[reset_index].death_timer = 16.0f;

            if (!demo_mode_active) {
                reset_vec2_t mouse_pos(320.0f, 140.0f);
                *(reset_vec2_t *)&ui_mouse_x = mouse_pos;
            }
        }

        memset(
            player_state_table[render_overlay_player_index].perk_counts,
            0,
            sizeof(player_state_table[0].perk_counts));

        {
            unsigned char *collision_flag = &creature_pool[0].collision_flag;
            do {
                *collision_flag = 0;
                collision_flag += sizeof(creature_t);
            } while ((int)collision_flag < (int)&creature_pool[0x180].collision_flag);
        }

        render_overlay_player_index += 1;
    } while (render_overlay_player_index < 2);

    render_overlay_player_index = 0;
}
