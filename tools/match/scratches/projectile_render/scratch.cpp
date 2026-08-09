#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int bullet_trail_texture;
extern int particles_texture;
extern int projectile_texture;
extern int projectile_bullet_texture;
extern int perk_id_sharpshooter;
extern int perk_id_ion_gun_master;
extern int quest_spawn_timeline;

void effect_select_texture(int effect_id);
int creature_find_in_radius(float *pos, float radius, int start_index);
vec2f_t *__stdcall D3DXVec2Normalize(
    vec2f_t *dst,
    const vec2f_t *src);
}

struct projectile_render_vec2_t {
    float x;
    float y;

    projectile_render_vec2_t() {}

    projectile_render_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    projectile_render_vec2_t operator+(
        const projectile_render_vec2_t &other) const
    {
        return projectile_render_vec2_t(x + other.x, y + other.y);
    }

    projectile_render_vec2_t operator-(
        const projectile_render_vec2_t &other) const
    {
        return projectile_render_vec2_t(x - other.x, y - other.y);
    }

    projectile_render_vec2_t operator-(float value) const
    {
        return projectile_render_vec2_t(x - value, y - value);
    }

    projectile_render_vec2_t operator*(float scale) const
    {
        return projectile_render_vec2_t(x * scale, y * scale);
    }

    projectile_render_vec2_t &operator+=(
        const projectile_render_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }

    projectile_render_vec2_t &operator-=(
        const projectile_render_vec2_t &other)
    {
        x -= other.x;
        y -= other.y;
        return *this;
    }

    projectile_render_vec2_t &operator-=(float value)
    {
        x -= value;
        y -= value;
        return *this;
    }

    float length() const
    {
        return (float)sqrt(x * x + y * y);
    }
};

extern "C" projectile_render_vec2_t camera_offset;

#define camera_offset_x camera_offset.x
#define camera_offset_y camera_offset.y

static __inline float projectile_render_clamp(float value)
{
    if (value > 1.0f) {
        return 1.0f;
    }
    if (value < 0.0f) {
        return 0.0f;
    }
    return value;
}

extern "C" void projectile_render(float transition_alpha)
{
    int player_index;
    int projectile_index;
    int secondary_index;

    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_color(
        1.0f,
        0.0f,
        0.0f,
        transition_alpha * 0.5f);
    grim_interface_ptr->grim_set_color_slot(
        2,
        0.0f,
        0.0f,
        0.0f,
        transition_alpha * 0.2f);
    grim_interface_ptr->grim_set_color_slot(
        3,
        0.0f,
        0.0f,
        0.0f,
        transition_alpha * 0.2f);
    grim_interface_ptr->grim_bind_texture(bullet_trail_texture, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 0.5f);

    for (player_index = 0;
         player_index < config_blob.player_count;
         ++player_index) {
        player_state_t *player = &player_state_table[player_index];
        if (player->health > 0.0f) {
            float heading = player->aim_heading - 1.5707964f;
            projectile_render_vec2_t player_pos =
                *(projectile_render_vec2_t *)&player->position;
            projectile_render_vec2_t end_pos =
                player_pos
                + projectile_render_vec2_t(
                      (float)cos(heading), (float)sin(heading))
                    * 512.0f;
            float start_heading = heading - 0.150915f;
            projectile_render_vec2_t start_pos =
                player_pos
                + projectile_render_vec2_t(
                      (float)cos(start_heading), (float)sin(start_heading))
                    * 15.0f;
            projectile_render_vec2_t half_width =
                projectile_render_vec2_t(
                    (float)cos(player->aim_heading),
                    (float)sin(player->aim_heading))
                * 1.1f;
            projectile_render_vec2_t start_screen =
                camera_offset + start_pos;
            projectile_render_vec2_t point0 = start_screen - half_width;
            projectile_render_vec2_t point1 = start_screen + half_width;
            projectile_render_vec2_t end_screen_result =
                camera_offset + end_pos;
            projectile_render_vec2_t end_screen;
            end_screen.x = end_screen_result.x;
            end_screen.y = end_screen_result.y;
            projectile_render_vec2_t point2 = end_screen + half_width;
            projectile_render_vec2_t point3 = end_screen - half_width;

            if (player->perk_counts[perk_id_sharpshooter] > 0) {
                grim_interface_ptr->grim_set_config_var(0x14, 2u);
                grim_interface_ptr->grim_begin_batch();
                grim_interface_ptr->grim_draw_quad_points(
                    point0.x,
                    point0.y,
                    point1.x,
                    point1.y,
                    point2.x,
                    point2.y,
                    point3.x,
                    point3.y);
                grim_interface_ptr->grim_end_batch();
                grim_interface_ptr->grim_set_config_var(0x14, 6u);
            }
        }
    }

    grim_interface_ptr->grim_set_color_slot(
        0, 0.5f, 0.5f, 0.5f, 0.0f);
    grim_interface_ptr->grim_set_color_slot(
        1, 0.5f, 0.5f, 0.5f, 0.0f);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);

    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        projectile_vel_y_block_t *tail = &projectile->pos.tail.vy;
        projectile_type_id_t type_id = tail->type_id;
        if (!projectile->active
            || !((int)type_id <= 7
                || type_id == PROJECTILE_TYPE_SPLITTER_GUN)) {
            continue;
        }
        if (type_id == PROJECTILE_TYPE_NONE) {
            projectile->active = 0;
        }

        float alpha = projectile_render_clamp(
            tail->life_timer);
        grim_interface_ptr->grim_set_color_slot(
            2, 0.5f, 0.5f, 0.5f, alpha * transition_alpha);
        grim_interface_ptr->grim_set_color_slot(
            3, 0.5f, 0.5f, 0.5f, alpha * transition_alpha);

        type_id = tail->type_id;
        projectile_render_vec2_t point0;
        projectile_render_vec2_t point1;
        projectile_render_vec2_t point2;
        projectile_render_vec2_t point3;
        if (type_id == PROJECTILE_TYPE_ASSAULT_RIFLE) {
            projectile_render_vec2_t current_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position;
            projectile_render_vec2_t current;
            current.x = current_result.x;
            current.y = current_result.y;
            projectile_render_vec2_t half_width =
                *(projectile_render_vec2_t *)&projectile->pos.tail.velocity;
            point0 = current - half_width;
            point1 = current + half_width;
            projectile_render_vec2_t origin_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->pos.origin;
            projectile_render_vec2_t origin;
            origin.x = origin_result.x;
            origin.y = origin_result.y;
            point2 = origin + half_width;
            point3 = origin - half_width;
        } else if (type_id == PROJECTILE_TYPE_PISTOL) {
            projectile_render_vec2_t half_width =
                *(projectile_render_vec2_t *)&projectile->pos.tail.velocity
                * 1.2f;
            projectile_render_vec2_t current_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position;
            projectile_render_vec2_t current = current_result;
            projectile_render_vec2_t origin_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->pos.origin;
            projectile_render_vec2_t origin = origin_result;
            point0 = current - half_width;
            point1 = current + half_width;
            point2 = origin + half_width;
            point3 = origin - half_width;
        } else if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
            grim_interface_ptr->grim_set_color_slot(
                2, 0.2f, 0.5f, 1.0f, alpha);
            grim_interface_ptr->grim_set_color_slot(
                3, 0.2f, 0.5f, 1.0f, alpha);
            projectile_render_vec2_t half_width =
                *(projectile_render_vec2_t *)&projectile->pos.tail.velocity
                * 1.1f;
            projectile_render_vec2_t current_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position;
            projectile_render_vec2_t current = current_result;
            projectile_render_vec2_t origin_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->pos.origin;
            projectile_render_vec2_t origin = origin_result;
            point0 = current - half_width;
            point1 = current + half_width;
            point2 = origin + half_width;
            point3 = origin - half_width;
        } else {
            projectile_render_vec2_t half_width =
                *(projectile_render_vec2_t *)&projectile->pos.tail.velocity
                * 0.7f;
            projectile_render_vec2_t current_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position;
            projectile_render_vec2_t current = current_result;
            point0 = current - half_width;
            point1 = current + half_width;
            projectile_render_vec2_t origin_result =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->pos.origin;
            projectile_render_vec2_t origin = origin_result;
            point2 = origin + half_width;
            point3 = origin - half_width;
        }
        grim_interface_ptr->grim_draw_quad_points(
            point0.x,
            point0.y,
            point1.x,
            point1.y,
            point2.x,
            point2.y,
            point3.x,
            point3.y);
    }
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(13);
    grim_interface_ptr->grim_set_rotation(0.0f);

    player_state_t *overlay_player =
        &player_state_table[render_overlay_player_index];
    if (overlay_player->muzzle_flash_alpha > 0.0f) {
        float heading = overlay_player->aim_heading
            - 1.5707964f
            - 0.150915f;
        projectile_render_vec2_t flash(
            (float)cos(heading) * 15.0f,
            (float)sin(heading) * 15.0f);
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            transition_alpha * overlay_player->muzzle_flash_alpha);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            camera_offset_x
                + player_state_table[render_overlay_player_index].pos_x
                + flash.x
                - 80.0f,
            camera_offset_y
                + player_state_table[render_overlay_player_index].pos_y
                + flash.y
                - 80.0f,
            160.0f,
            160.0f);
        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_begin_batch();
    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        projectile_pos_y_block_t *plasma = &projectile->pos;
        projectile_type_id_t &type_id = plasma->tail.vy.type_id;
        if (!projectile->active
            || !(type_id == PROJECTILE_TYPE_PLASMA_RIFLE
                || type_id == PROJECTILE_TYPE_PLASMA_MINIGUN
                || type_id == PROJECTILE_TYPE_SPIDER_PLASMA
                || type_id == PROJECTILE_TYPE_SHRINKIFIER
                || type_id == PROJECTILE_TYPE_PLASMA_CANNON)) {
            continue;
        }

        if (plasma->tail.vy.life_timer == 0.4f) {
            if (type_id == PROJECTILE_TYPE_PLASMA_RIFLE) {
                float dx = projectile->pos.origin_x - projectile->pos_x;
                float dy = projectile->pos.tail.origin_y
                    - projectile->pos.pos_y;
                float distance = (float)sqrt(dx * dx + dy * dy);
                int distance_i = (int)distance;
                int divisor_i = (int)(
                    plasma->tail.vy.speed_scale * 2.5f);
                int segment_count = distance_i / divisor_i;
                if (segment_count > 8) {
                    segment_count = 8;
                }

                float heading = projectile->angle + 1.5707964f;
                float step_x = (float)cos(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.5f;
                float step_y = (float)sin(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.5f;
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.4f);
                for (int segment_index = 0;
                     segment_index < segment_count;
                     ++segment_index) {
                    float segment = (float)segment_index;
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x
                            + segment * step_x - 11.0f,
                        camera_offset_y + projectile->pos.pos_y
                            + segment * step_y - 11.0f,
                        22.0f,
                        22.0f);
                }

                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.45f);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 28.0f,
                    camera_offset_y + projectile->pos.pos_y - 28.0f,
                    56.0f,
                    56.0f);
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.3f);
                if (config_blob.flame_glow_enabled) {
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x - 128.0f,
                        camera_offset_y + projectile->pos.pos_y - 128.0f,
                        256.0f,
                        256.0f);
                }
            } else if (type_id == PROJECTILE_TYPE_PLASMA_MINIGUN) {
                float dx = projectile->pos.origin_x - projectile->pos_x;
                float dy = projectile->pos.tail.origin_y
                    - projectile->pos.pos_y;
                float distance = (float)sqrt(dx * dx + dy * dy);
                int distance_i = (int)distance;
                int divisor_i = (int)(
                    plasma->tail.vy.speed_scale * 2.1f);
                int segment_count = distance_i / divisor_i;
                if (segment_count > 3) {
                    segment_count = 3;
                }

                float heading = projectile->angle + 1.5707964f;
                float step_x = (float)cos(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.1f;
                float step_y = (float)sin(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.1f;
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.4f);
                for (int segment_index = 0;
                     segment_index < segment_count;
                     ++segment_index) {
                    float segment = (float)segment_index;
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x
                            + segment * step_x - 6.0f,
                        camera_offset_y + projectile->pos.pos_y
                            + segment * step_y - 6.0f,
                        12.0f,
                        12.0f);
                }

                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.45f);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 8.0f,
                    camera_offset_y + projectile->pos.pos_y - 8.0f,
                    16.0f,
                    16.0f);
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.15f);
                if (config_blob.flame_glow_enabled) {
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x - 60.0f,
                        camera_offset_y + projectile->pos.pos_y - 60.0f,
                        120.0f,
                        120.0f);
                }
            } else if (type_id == PROJECTILE_TYPE_PLASMA_CANNON) {
                int distance_i = (int)projectile_render_vec2_t(
                    projectile->pos.origin_x - projectile->pos_x,
                    projectile->pos.tail.origin_y
                        - projectile->pos.pos_y).length();
                int divisor_i = (int)(
                    plasma->tail.vy.speed_scale * 3.5f);
                int segment_count = distance_i / divisor_i;
                if (segment_count > 18) {
                    segment_count = 18;
                }

                float heading = projectile->angle + 1.5707964f;
                float step_x = (float)cos(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.6f;
                float step_y = (float)sin(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.6f;
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.4f);
                for (int segment_index = 0;
                     segment_index < segment_count;
                     ++segment_index) {
                    float segment = (float)segment_index;
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x
                            + segment * step_x - 22.0f,
                        camera_offset_y + projectile->pos.pos_y
                            + segment * step_y - 22.0f,
                        44.0f,
                        44.0f);
                }

                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.45f);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 42.0f,
                    camera_offset_y + projectile->pos.pos_y - 42.0f,
                    84.0f,
                    84.0f);
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.4f);
                if (config_blob.flame_glow_enabled) {
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x - 128.0f,
                        camera_offset_y + projectile->pos.pos_y - 128.0f,
                        256.0f,
                        256.0f);
                }
            } else if (type_id == PROJECTILE_TYPE_SPIDER_PLASMA) {
                int distance_i = (int)projectile_render_vec2_t(
                    projectile->pos.origin_x - projectile->pos_x,
                    projectile->pos.tail.origin_y
                        - projectile->pos.pos_y).length();
                int divisor_i = (int)(
                    plasma->tail.vy.speed_scale * 2.1f);
                int segment_count = distance_i / divisor_i;
                if (segment_count > 3) {
                    segment_count = 3;
                }

                float heading = projectile->angle + 1.5707964f;
                float step_x = (float)cos(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.1f;
                float step_y = (float)sin(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.1f;
                grim_interface_ptr->grim_set_color(
                    0.3f, 1.0f, 0.3f, transition_alpha * 0.4f);
                for (int segment_index = 0;
                     segment_index < segment_count;
                     ++segment_index) {
                    float segment = (float)segment_index;
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x
                            + segment * step_x - 6.0f,
                        camera_offset_y + projectile->pos.pos_y
                            + segment * step_y - 6.0f,
                        12.0f,
                        12.0f);
                }

                grim_interface_ptr->grim_set_color(
                    0.3f, 1.0f, 0.3f, transition_alpha * 0.45f);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 8.0f,
                    camera_offset_y + projectile->pos.pos_y - 8.0f,
                    16.0f,
                    16.0f);
                grim_interface_ptr->grim_set_color(
                    0.3f, 1.0f, 0.3f, transition_alpha * 0.15f);
                if (config_blob.flame_glow_enabled) {
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x - 60.0f,
                        camera_offset_y + projectile->pos.pos_y - 60.0f,
                        120.0f,
                        120.0f);
                }
            } else if (type_id == PROJECTILE_TYPE_SHRINKIFIER) {
                int distance_i = (int)projectile_render_vec2_t(
                    projectile->pos.origin_x - projectile->pos_x,
                    projectile->pos.tail.origin_y
                        - projectile->pos.pos_y).length();
                int divisor_i = (int)(
                    plasma->tail.vy.speed_scale * 2.1f);
                int segment_count = distance_i / divisor_i;
                if (segment_count > 3) {
                    segment_count = 3;
                }

                float heading = projectile->angle + 1.5707964f;
                float step_x = (float)cos(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.1f;
                float step_y = (float)sin(heading)
                    * plasma->tail.vy.speed_scale
                    * 2.1f;
                grim_interface_ptr->grim_set_color(
                    0.3f, 0.3f, 1.0f, transition_alpha * 0.4f);
                for (int segment_index = 0;
                     segment_index < segment_count;
                     ++segment_index) {
                    float segment = (float)segment_index;
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x
                            + segment * step_x - 6.0f,
                        camera_offset_y + projectile->pos.pos_y
                            + segment * step_y - 6.0f,
                        12.0f,
                        12.0f);
                }

                grim_interface_ptr->grim_set_color(
                    0.3f, 0.3f, 1.0f, transition_alpha * 0.45f);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 8.0f,
                    camera_offset_y + projectile->pos.pos_y - 8.0f,
                    16.0f,
                    16.0f);
                grim_interface_ptr->grim_set_color(
                    0.3f, 0.3f, 1.0f, transition_alpha * 0.15f);
                if (config_blob.flame_glow_enabled) {
                    grim_interface_ptr->grim_draw_quad(
                        camera_offset_x + projectile->pos_x - 60.0f,
                        camera_offset_y + projectile->pos.pos_y - 60.0f,
                        120.0f,
                        120.0f);
                }
            }
        } else {
            float fade = projectile_render_clamp(
                plasma->tail.vy.life_timer * 2.5f);
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, fade * transition_alpha);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 28.0f,
                camera_offset_y + projectile->pos.pos_y - 28.0f,
                56.0f,
                56.0f);
        }
    }
    grim_interface_ptr->grim_end_batch();

    float ion_scale = 1.0f;
    if (perk_count_get(perk_id_ion_gun_master) != 0) {
        ion_scale = 1.2f;
    }
    grim_interface_ptr->grim_bind_texture(projectile_texture, 0);
    grim_interface_ptr->grim_begin_batch();

    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        projectile_tail_t *primary = &projectile->pos.tail;
        if (!projectile->active) {
            continue;
        }
        projectile_type_id_t &type_id = primary->vy.type_id;
        float life = primary->vy.life_timer;

        if (type_id == PROJECTILE_TYPE_PULSE_GUN) {
            if (primary->vy.life_timer == 0.4f) {
                float pulse_scale = projectile_render_vec2_t(
                    projectile->pos.origin_x - projectile->pos_x,
                    primary->origin_y - projectile->pos.pos_y).length()
                    * 0.01f;
                grim_interface_ptr->grim_set_rotation(projectile->angle);
                grim_interface_ptr->grim_set_atlas_frame(2, 0);
                grim_interface_ptr->grim_set_color(
                    0.1f, 0.6f, 0.2f, transition_alpha * 0.7f);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x
                        - pulse_scale * 8.0f,
                    camera_offset_y + projectile->pos.pos_y
                        - pulse_scale * 8.0f,
                    pulse_scale * 16.0f,
                    pulse_scale * 16.0f);
            } else {
                float fade = projectile_render_clamp(life * 2.5f);
                grim_interface_ptr->grim_set_rotation(projectile->angle);
                grim_interface_ptr->grim_set_atlas_frame(2, 0);
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, fade * transition_alpha);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 28.0f,
                    camera_offset_y + projectile->pos.pos_y - 28.0f,
                    56.0f,
                    56.0f);
            }
            continue;
        }

        if (type_id == PROJECTILE_TYPE_SPLITTER_GUN) {
            if (primary->vy.life_timer != 0.4f) {
                continue;
            }
            float size = projectile_render_vec2_t(
                projectile->pos.origin_x - projectile->pos_x,
                primary->origin_y - projectile->pos.pos_y).length();
            if (size > 20.0f) {
                size = 20.0f;
            }
            grim_interface_ptr->grim_set_rotation(projectile->angle);
            grim_interface_ptr->grim_set_atlas_frame(4, 3);
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - size * 0.5f,
                camera_offset_y + projectile->pos.pos_y - size * 0.5f,
                size,
                size);
            continue;
        }

        if (type_id == PROJECTILE_TYPE_BLADE_GUN) {
            if (primary->vy.life_timer != 0.4f) {
                continue;
            }
            float size = projectile_render_vec2_t(
                projectile->pos.origin_x - projectile->pos_x,
                primary->origin_y - projectile->pos.pos_y).length();
            if (size > 20.0f) {
                size = 20.0f;
            }
            grim_interface_ptr->grim_set_rotation(
                (float)projectile_index * 0.1f
                - (float)quest_spawn_timeline * 0.1f);
            grim_interface_ptr->grim_set_atlas_frame(4, 6);
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - size * 0.5f,
                camera_offset_y + projectile->pos.pos_y - size * 0.5f,
                size,
                size);
            continue;
        }

        if (!(type_id == PROJECTILE_TYPE_ION_RIFLE
            || type_id == PROJECTILE_TYPE_ION_MINIGUN
            || type_id == PROJECTILE_TYPE_ION_CANNON
            || type_id == PROJECTILE_TYPE_FIRE_BULLETS)) {
            continue;
        }

        if (primary->vy.life_timer == 0.4f) {
            float effect_scale;
            if (type_id == PROJECTILE_TYPE_ION_MINIGUN) {
                effect_scale = 1.05f;
            } else if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
                effect_scale = 2.2f;
            } else {
                effect_scale = 0.8f;
                if (type_id != PROJECTILE_TYPE_FIRE_BULLETS) {
                    effect_scale = 3.5f;
                }
            }

            grim_interface_ptr->grim_set_atlas_frame(2, 2);
            projectile_render_vec2_t direction_result(
                projectile->pos.origin_x - projectile->pos_x,
                primary->origin_y - projectile->pos.pos_y);
            vec2f_t direction = *(vec2f_t *)&direction_result;
            float distance = direction_result.length();
            D3DXVec2Normalize(&direction, &direction);
            if (primary->vy.type_id
                == PROJECTILE_TYPE_FIRE_BULLETS) {
                grim_interface_ptr->grim_set_color(
                    1.0f, 0.6f, 0.1f, transition_alpha);
            } else {
                grim_interface_ptr->grim_set_color(
                    0.5f, 0.6f, 1.0f, transition_alpha);
            }
            grim_interface_ptr->grim_set_atlas_frame(4, 2);

            float half_size = effect_scale * 16.0f;
            float base_x = camera_offset_x + projectile->pos_x
                - half_size;
            float base_y = camera_offset_y + projectile->pos.pos_y
                - half_size;
            float span = distance;
            float along = 0.0f;
            if (distance > 256.0f) {
                span = 256.0f;
                along = distance - 256.0f;
            }
            float step = effect_scale * 3.1f;
            if (step > 9.0f) {
                step = 9.0f;
            }
            float first = along;
            float size = effect_scale * 32.0f;
            while (along < distance) {
                float alpha = (along - first) / span
                    * transition_alpha;
                if (type_id == PROJECTILE_TYPE_FIRE_BULLETS) {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 0.6f, 0.1f, alpha);
                } else {
                    grim_interface_ptr->grim_set_color(
                        0.5f, 0.6f, 1.0f, alpha);
                }
                grim_interface_ptr->grim_draw_quad(
                    direction.x * along + base_x,
                    direction.y * along + base_y,
                    size,
                    size);
                along += step;
            }

            grim_interface_ptr->grim_set_rotation(projectile->angle);
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 0.7f, transition_alpha);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - half_size,
                camera_offset_y + projectile->pos.pos_y - half_size,
                size,
                size);
        } else {
            grim_interface_ptr->grim_set_rotation(projectile->angle);
            grim_interface_ptr->grim_set_atlas_frame(4, 2);
            float fade = projectile_render_clamp(life * 2.5f);

            projectile_render_vec2_t direction_result(
                projectile->pos.origin_x - projectile->pos_x,
                primary->origin_y - projectile->pos.pos_y);
            vec2f_t direction;
            direction.x = direction_result.x;
            direction.y = direction_result.y;
            float distance = direction_result.length();
            D3DXVec2Normalize(&direction, &direction);

            float effect_scale;
            if (type_id == PROJECTILE_TYPE_ION_MINIGUN) {
                effect_scale = 1.05f;
            } else if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
                effect_scale = 2.2f;
            } else {
                effect_scale = 0.8f;
                if (type_id != PROJECTILE_TYPE_FIRE_BULLETS) {
                    effect_scale = 3.5f;
                }
            }

            grim_interface_ptr->grim_set_atlas_frame(4, 2);
            float half_size = effect_scale * 16.0f;
            float base_x = camera_offset_x + projectile->pos_x
                - half_size;
            float base_y = camera_offset_y + projectile->pos.pos_y
                - half_size;
            float span = distance;
            float along = 0.0f;
            if (distance > 256.0f) {
                span = 256.0f;
                along = distance - 256.0f;
            }
            float step = effect_scale * 3.1f;
            if (step > 9.0f) {
                step = 9.0f;
            }
            float first = along;
            float size = effect_scale * 32.0f;
            while (along < distance) {
                float alpha = (along - first) / span
                    * fade
                    * transition_alpha;
                if (primary->vy.type_id
                    == PROJECTILE_TYPE_FIRE_BULLETS) {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 0.6f, 0.1f, alpha);
                } else {
                    grim_interface_ptr->grim_set_color(
                        0.5f, 0.6f, 1.0f, alpha);
                }
                grim_interface_ptr->grim_draw_quad(
                    direction.x * along + base_x,
                    direction.y * along + base_y,
                    size,
                    size);
                along += step;
            }

            float head_alpha = fade * transition_alpha;
            grim_interface_ptr->grim_set_color(
                0.5f, 0.6f, 1.0f, head_alpha);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 16.0f,
                camera_offset_y + projectile->pos.pos_y - 16.0f,
                32.0f,
                32.0f);

            if (type_id != PROJECTILE_TYPE_FIRE_BULLETS) {
                float radius = effect_scale * ion_scale * 40.0f;
                int creature_index = creature_find_in_radius(
                    &projectile->pos_x,
                    radius,
                    1);
                while (creature_index != -1) {
                    grim_interface_ptr->grim_set_uv_point(0, 0.625f, 0.0f);
                    grim_interface_ptr->grim_set_uv_point(1, 0.625f, 0.25f);
                    grim_interface_ptr->grim_set_uv_point(2, 0.625f, 0.25f);
                    grim_interface_ptr->grim_set_uv_point(3, 0.625f, 0.0f);

                    projectile_render_vec2_t arc_result =
                        *(projectile_render_vec2_t *)
                             &creature_pool[creature_index].pos_x
                        - *(projectile_render_vec2_t *)&projectile->position;
                    projectile_render_vec2_t arc = arc_result;
                    D3DXVec2Normalize(
                        (vec2f_t *)&arc, (const vec2f_t *)&arc);
                    float old_arc_x = arc.x;
                    arc.x = -arc.y;
                    arc.y = old_arc_x;
                    projectile_render_vec2_t start_result =
                        camera_offset
                        + *(projectile_render_vec2_t *)&projectile->position;
                    projectile_render_vec2_t start;
                    start.x = start_result.x;
                    start.y = start_result.y;
                    projectile_render_vec2_t side = arc * effect_scale;
                    projectile_render_vec2_t strip0 =
                        start - side * 10.0f;
                    projectile_render_vec2_t strip1 =
                        start + side * 10.0f;
                    projectile_render_vec2_t end_result =
                        camera_offset
                        + *(projectile_render_vec2_t *)
                             &creature_pool[creature_index].pos_x;
                    projectile_render_vec2_t end = end_result;
                    projectile_render_vec2_t strip2 =
                        end + side * 10.0f;
                    projectile_render_vec2_t strip3 =
                        end - side * 10.0f;

                    grim_interface_ptr->grim_draw_quad_points(
                        strip0.x,
                        strip0.y,
                        strip1.x,
                        strip1.y,
                        strip2.x,
                        strip2.y,
                        strip3.x,
                        strip3.y);
                    projectile_render_vec2_t widen_result =
                        arc * effect_scale * 4.0f;
                    projectile_render_vec2_t widen = widen_result;
                    strip0 -= widen;
                    strip1 += widen;
                    strip2 += widen;
                    strip3 -= widen;
                    grim_interface_ptr->grim_draw_quad_points(
                        strip0.x,
                        strip0.y,
                        strip1.x,
                        strip1.y,
                        strip2.x,
                        strip2.y,
                        strip3.x,
                        strip3.y);
                    grim_interface_ptr->grim_set_atlas_frame(4, 2);
                    float half_size = effect_scale * 16.0f;
                    grim_interface_ptr->grim_draw_quad(
                        end.x - half_size,
                        end.y - half_size,
                        size,
                        size);
                    creature_index = creature_find_in_radius(
                        &projectile->pos_x,
                        radius,
                        creature_index + 1);
                }
            }
        }
    }
    grim_interface_ptr->grim_end_batch();

    float plague_phase =
        ((float)survival_elapsed_ms * 0.001f) * 9.0f;
    grim_interface_ptr->grim_set_config_var(0x13, 1u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_begin_batch();
    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        if (!projectile->active
            || projectile->pos.tail.vy.type_id
                != PROJECTILE_TYPE_PLAGUE_SPREADER) {
            continue;
        }

        if (projectile->pos.tail.vy.life_timer == 0.4f) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 30.0f,
                camera_offset_y + projectile->pos.pos_y - 30.0f,
                60.0f,
                60.0f);

            float heading = projectile->angle + 1.5707964f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x
                    - 30.0f
                    + (float)cos(heading) * 15.0f,
                camera_offset_y + projectile->pos.pos_y
                    - 30.0f
                    + (float)sin(heading) * 15.0f,
                60.0f,
                60.0f);

            float phase = (float)projectile_index + plague_phase;
            float phase_cos = (float)cos(phase);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x
                    - 31.0f
                    + phase_cos * phase_cos,
                camera_offset_y + projectile->pos.pos_y
                    - 31.0f
                    + (float)sin(phase) * 11.0f,
                52.0f,
                52.0f);

            float phase_120 = phase + 2.0943952f;
            float phase_120_sin = (float)sin(phase_120);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x
                    - 31.0f
                    + (float)cos(phase_120) * 10.0f,
                camera_offset_y + projectile->pos.pos_y
                    - 31.0f
                    + phase_120_sin * 10.0f,
                62.0f,
                62.0f);

            float phase_240 = phase + 4.1887903f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x
                    - 31.0f
                    + (float)cos(phase_240) * 10.0f,
                camera_offset_y + projectile->pos.pos_y
                    - 31.0f
                    + (float)sin(phase_240) * phase_120_sin,
                62.0f,
                62.0f);
        } else {
            float fade = projectile_render_clamp(
                projectile->pos.tail.vy.life_timer * 2.5f);
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, fade * transition_alpha);
            float size = fade * 40.0f + 32.0f;
            float half_size = fade * 20.0f + 16.0f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - half_size,
                camera_offset_y + projectile->pos.pos_y - half_size,
                size,
                size);
        }
    }
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(13);
    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, transition_alpha);
    grim_interface_ptr->grim_begin_batch();
    projectile_t *fire_type_owner = &projectile_pool[0x5f];
    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        if (projectile->active
            && fire_type_owner->pos.tail.vy.type_id
                == PROJECTILE_TYPE_FIRE_BULLETS
            && projectile->pos.tail.vy.life_timer == 0.4f) {
            grim_interface_ptr->grim_set_rotation(projectile->angle);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 32.0f,
                camera_offset_y + projectile->pos.pos_y - 32.0f,
                64.0f,
                64.0f);
        }
    }
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_color(
        0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
    grim_interface_ptr->grim_bind_texture(projectile_bullet_texture, 0);
    grim_interface_ptr->grim_begin_batch();
    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        if (!projectile->active
            || projectile->pos.tail.vy.life_timer != 0.4f) {
            continue;
        }
        projectile_type_id_t type_id = projectile->pos.tail.vy.type_id;
        if (type_id == PROJECTILE_TYPE_PLASMA_RIFLE
            || type_id == PROJECTILE_TYPE_PLASMA_MINIGUN
            || type_id == PROJECTILE_TYPE_PULSE_GUN) {
            continue;
        }
        grim_interface_ptr->grim_set_rotation(projectile->angle);
        if (type_id == PROJECTILE_TYPE_PISTOL) {
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 3.0f,
                camera_offset_y + projectile->pos.pos_y - 3.0f,
                6.0f,
                6.0f);
        } else if ((int)type_id == 4) {
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 4.0f,
                camera_offset_y + projectile->pos.pos_y - 4.0f,
                8.0f,
                8.0f);
        } else {
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 2.0f,
                camera_offset_y + projectile->pos.pos_y - 2.0f,
                4.0f,
                4.0f);
        }
    }
    grim_interface_ptr->grim_end_batch();

    if (config_blob.flame_glow_enabled) {
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 2u);
        grim_interface_ptr->grim_bind_texture(particles_texture, 0);
        effect_select_texture(13);
        grim_interface_ptr->grim_begin_batch();
        for (secondary_index = 0;
             secondary_index < 0x40;
             ++secondary_index) {
            secondary_projectile_t *projectile =
                &secondary_projectile_pool[secondary_index];
            if (projectile->active) {
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha * 0.48f);
                float heading = projectile->angle - 1.5707964f;
                projectile_render_vec2_t draw_pos =
                    camera_offset
                    + *(projectile_render_vec2_t *)&projectile->position
                    - projectile_render_vec2_t(
                          (float)cos(heading), (float)sin(heading))
                        * 5.0f
                    - 70.0f;
                grim_interface_ptr->grim_draw_quad(
                    draw_pos.x,
                    draw_pos.y,
                    140.0f,
                    140.0f);
            }
        }
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_color(
        0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
    grim_interface_ptr->grim_bind_texture(projectile_texture, 0);
    grim_interface_ptr->grim_set_atlas_frame(4, 3);
    grim_interface_ptr->grim_begin_batch();
    for (secondary_index = 0;
         secondary_index < 0x40;
         ++secondary_index) {
        secondary_projectile_t *projectile =
            &secondary_projectile_pool[secondary_index];
        if (!projectile->active
            || projectile->pos.vx.vy.type_id
                == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
            continue;
        }
        grim_interface_ptr->grim_set_rotation(projectile->angle);
        secondary_projectile_type_id_t type_id =
            projectile->pos.vx.vy.type_id;
        if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
            projectile_render_vec2_t draw_pos =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position;
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
            draw_pos -= 7.0f;
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x,
                draw_pos.y,
                14.0f,
                14.0f);
        } else if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
            projectile_render_vec2_t draw_pos =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position;
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
            draw_pos -= 5.0f;
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x,
                draw_pos.y,
                10.0f,
                10.0f);
        } else if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
            projectile_render_vec2_t draw_pos =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position;
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
            draw_pos -= 4.0f;
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x,
                draw_pos.y,
                8.0f,
                8.0f);
        }
    }
    grim_interface_ptr->grim_end_batch();

    if (!config_blob.flame_glow_enabled) {
        return;
    }
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(13);
    grim_interface_ptr->grim_begin_batch();
    for (secondary_index = 0;
         secondary_index < 0x40;
         ++secondary_index) {
        secondary_projectile_t *projectile =
            &secondary_projectile_pool[secondary_index];
        if (!projectile->active) {
            continue;
        }
        secondary_projectile_type_id_t type_id =
            projectile->pos.vx.vy.type_id;
        if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
            grim_interface_ptr->grim_set_color(
                0.7f, 0.7f, 1.0f, transition_alpha * 0.158f);
            float heading = projectile->angle - 1.5707964f;
            projectile_render_vec2_t draw_pos =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position
                - projectile_render_vec2_t(
                          (float)cos(heading), (float)sin(heading))
                    * 9.0f
                - 15.0f;
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x,
                draw_pos.y,
                30.0f,
                30.0f);
        } else if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha * 0.68f);
            float heading = projectile->angle - 1.5707964f;
            projectile_render_vec2_t draw_pos =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position
                - projectile_render_vec2_t(
                          (float)cos(heading), (float)sin(heading))
                    * 9.0f
                - 30.0f;
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x,
                draw_pos.y,
                60.0f,
                60.0f);
        } else if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha * 0.58f);
            float heading = projectile->angle - 1.5707964f;
            projectile_render_vec2_t draw_pos =
                camera_offset
                + *(projectile_render_vec2_t *)&projectile->position
                - projectile_render_vec2_t(
                          (float)cos(heading), (float)sin(heading))
                    * 9.0f
                - 20.0f;
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x,
                draw_pos.y,
                40.0f,
                40.0f);
        }
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
}
