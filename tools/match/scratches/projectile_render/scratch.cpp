#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int bullet_trail_texture;
extern int particles_texture;
extern int projectile_texture;
extern int projectile_bullet_texture;
extern float camera_offset_x;
extern float camera_offset_y;
extern int perk_id_sharpshooter;
extern int perk_id_ion_gun_master;
extern int quest_spawn_timeline;

void effect_select_texture(int effect_id);
int creature_find_in_radius(float *pos, float radius, int start_index);
vec2f_t *__stdcall vec2_normalize_dispatch(
    vec2f_t *dst,
    const vec2f_t *src);
}

static __inline float projectile_render_clamp(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
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
            float end_x = player->pos_x + (float)cos(heading) * 512.0f;
            float end_y = player->pos_y + (float)sin(heading) * 512.0f;
            float start_heading = heading - 0.150915f;
            float start_x =
                player->pos_x + (float)cos(start_heading) * 15.0f;
            float start_y =
                player->pos_y + (float)sin(start_heading) * 15.0f;
            float half_x = (float)cos(player->aim_heading) * 1.1f;
            float half_y = (float)sin(player->aim_heading) * 1.1f;

            if (player->perk_counts[perk_id_sharpshooter] > 0) {
                grim_interface_ptr->grim_set_config_var(0x14, 2u);
                grim_interface_ptr->grim_begin_batch();
                grim_interface_ptr->grim_draw_quad_points(
                    camera_offset_x + start_x - half_x,
                    camera_offset_y + start_y - half_y,
                    camera_offset_x + start_x + half_x,
                    camera_offset_y + start_y + half_y,
                    camera_offset_x + end_x + half_x,
                    camera_offset_y + end_y + half_y,
                    camera_offset_x + end_x - half_x,
                    camera_offset_y + end_y - half_y);
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
        projectile_type_id_t type_id = projectile->pos.tail.vy.type_id;
        if (!projectile->active
            || !((int)type_id <= 7
                || type_id == PROJECTILE_TYPE_SPLITTER_GUN)) {
            continue;
        }
        if (type_id == PROJECTILE_TYPE_NONE) {
            projectile->active = 0;
        }

        float alpha = projectile_render_clamp(
            projectile->pos.tail.vy.life_timer);
        grim_interface_ptr->grim_set_color_slot(
            2, 0.5f, 0.5f, 0.5f, alpha * transition_alpha);
        grim_interface_ptr->grim_set_color_slot(
            3, 0.5f, 0.5f, 0.5f, alpha * transition_alpha);

        float x0;
        float y0;
        float x1;
        float y1;
        float x2;
        float y2;
        float x3;
        float y3;
        if (type_id == PROJECTILE_TYPE_ASSAULT_RIFLE) {
            float current_x = camera_offset_x + projectile->pos_x;
            float current_y = camera_offset_y + projectile->pos.pos_y;
            float origin_x = camera_offset_x + projectile->pos.origin_x;
            float origin_y = camera_offset_y + projectile->pos.tail.origin_y;
            x0 = current_x - projectile->pos.tail.vel_x;
            y0 = current_y - projectile->pos.tail.vy.vel_y;
            x1 = current_x + projectile->pos.tail.vel_x;
            y1 = current_y + projectile->pos.tail.vy.vel_y;
            x2 = origin_x + projectile->pos.tail.vel_x;
            y2 = origin_y + projectile->pos.tail.vy.vel_y;
            x3 = origin_x - projectile->pos.tail.vel_x;
            y3 = origin_y - projectile->pos.tail.vy.vel_y;
        } else if (type_id == PROJECTILE_TYPE_PISTOL) {
            float half_x = projectile->pos.tail.vel_x * 1.2f;
            float half_y = projectile->pos.tail.vy.vel_y * 1.2f;
            float current_x = camera_offset_x + projectile->pos_x;
            float current_y = camera_offset_y + projectile->pos.pos_y;
            float origin_x = camera_offset_x + projectile->pos.origin_x;
            float origin_y = camera_offset_y + projectile->pos.tail.origin_y;
            x0 = current_x - half_x;
            y0 = current_y - half_y;
            x1 = current_x + half_x;
            y1 = current_y + half_y;
            x2 = origin_x + half_x;
            y2 = origin_y + half_y;
            x3 = origin_x - half_x;
            y3 = origin_y - half_y;
        } else if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
            grim_interface_ptr->grim_set_color_slot(
                2, 0.2f, 0.5f, 1.0f, alpha);
            grim_interface_ptr->grim_set_color_slot(
                3, 0.2f, 0.5f, 1.0f, alpha);
            float half_x = projectile->pos.tail.vel_x * 1.1f;
            float half_y = projectile->pos.tail.vy.vel_y * 1.1f;
            float current_x = camera_offset_x + projectile->pos_x;
            float current_y = camera_offset_y + projectile->pos.pos_y;
            float origin_x = camera_offset_x + projectile->pos.origin_x;
            float origin_y = camera_offset_y + projectile->pos.tail.origin_y;
            x0 = current_x - half_x;
            y0 = current_y - half_y;
            x1 = current_x + half_x;
            y1 = current_y + half_y;
            x2 = origin_x + half_x;
            y2 = origin_y + half_y;
            x3 = origin_x - half_x;
            y3 = origin_y - half_y;
        } else {
            float half_x = projectile->pos.tail.vel_x * 0.7f;
            float half_y = projectile->pos.tail.vy.vel_y * 0.7f;
            float current_x = camera_offset_x + projectile->pos_x;
            float current_y = camera_offset_y + projectile->pos.pos_y;
            float origin_x = camera_offset_x + projectile->pos.origin_x;
            float origin_y = camera_offset_y + projectile->pos.tail.origin_y;
            x0 = current_x - half_x;
            y0 = current_y - half_y;
            x1 = current_x + half_x;
            y1 = current_y + half_y;
            x2 = origin_x + half_x;
            y2 = origin_y + half_y;
            x3 = origin_x - half_x;
            y3 = origin_y - half_y;
        }
        grim_interface_ptr->grim_draw_quad_points(
            x0, y0, x1, y1, x2, y2, x3, y3);
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
        float flash_x = (float)cos(heading) * 15.0f;
        float flash_y = (float)sin(heading) * 15.0f;
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            transition_alpha * overlay_player->muzzle_flash_alpha);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            camera_offset_x + overlay_player->pos_x + flash_x - 80.0f,
            camera_offset_y + overlay_player->pos_y + flash_y - 80.0f,
            160.0f,
            160.0f);
        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_begin_batch();
    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        projectile_type_id_t type_id = projectile->pos.tail.vy.type_id;
        if (!projectile->active
            || !(type_id == PROJECTILE_TYPE_PLASMA_RIFLE
                || type_id == PROJECTILE_TYPE_PLASMA_MINIGUN
                || type_id == PROJECTILE_TYPE_SPIDER_PLASMA
                || type_id == PROJECTILE_TYPE_SHRINKIFIER
                || type_id == PROJECTILE_TYPE_PLASMA_CANNON)) {
            continue;
        }

        float life = projectile->pos.tail.vy.life_timer;
        if (life != 0.4f) {
            float fade = projectile_render_clamp(life * 2.5f);
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, fade * transition_alpha);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 28.0f,
                camera_offset_y + projectile->pos.pos_y - 28.0f,
                56.0f,
                56.0f);
            continue;
        }

        if (type_id == PROJECTILE_TYPE_PLASMA_RIFLE) {
            float dx = projectile->pos.origin_x - projectile->pos_x;
            float dy = projectile->pos.tail.origin_y
                - projectile->pos.pos_y;
            int distance_i = (int)sqrt(dx * dx + dy * dy);
            int divisor_i = (int)(
                projectile->pos.tail.vy.speed_scale * 2.5f);
            int segment_count = distance_i / divisor_i;
            if (segment_count > 8) {
                segment_count = 8;
            }

            float heading = projectile->angle + 1.5707964f;
            float step_x = (float)cos(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.5f;
            float step_y = (float)sin(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.5f;
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha * 0.4f);
            for (int segment_index = 0;
                 segment_index < segment_count;
                 ++segment_index) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x
                        + (float)segment_index * step_x
                        - 11.0f,
                    camera_offset_y + projectile->pos.pos_y
                        + (float)segment_index * step_y
                        - 11.0f,
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
            if (config_blob.fx_detail_flag1) {
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
            int distance_i = (int)sqrt(dx * dx + dy * dy);
            int divisor_i = (int)(
                projectile->pos.tail.vy.speed_scale * 2.1f);
            int segment_count = distance_i / divisor_i;
            if (segment_count > 3) {
                segment_count = 3;
            }

            float heading = projectile->angle + 1.5707964f;
            float step_x = (float)cos(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.1f;
            float step_y = (float)sin(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.1f;
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha * 0.4f);
            for (int segment_index = 0;
                 segment_index < segment_count;
                 ++segment_index) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x
                        + (float)segment_index * step_x
                        - 6.0f,
                    camera_offset_y + projectile->pos.pos_y
                        + (float)segment_index * step_y
                        - 6.0f,
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
            if (config_blob.fx_detail_flag1) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 60.0f,
                    camera_offset_y + projectile->pos.pos_y - 60.0f,
                    120.0f,
                    120.0f);
            }
        } else if (type_id == PROJECTILE_TYPE_PLASMA_CANNON) {
            float dx = projectile->pos.origin_x - projectile->pos_x;
            float dy = projectile->pos.tail.origin_y
                - projectile->pos.pos_y;
            int distance_i = (int)sqrt(dx * dx + dy * dy);
            int divisor_i = (int)(
                projectile->pos.tail.vy.speed_scale * 3.5f);
            int segment_count = distance_i / divisor_i;
            if (segment_count > 18) {
                segment_count = 18;
            }

            float heading = projectile->angle + 1.5707964f;
            float step_x = (float)cos(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.6f;
            float step_y = (float)sin(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.6f;
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha * 0.4f);
            for (int segment_index = 0;
                 segment_index < segment_count;
                 ++segment_index) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x
                        + (float)segment_index * step_x
                        - 22.0f,
                    camera_offset_y + projectile->pos.pos_y
                        + (float)segment_index * step_y
                        - 22.0f,
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
            if (config_blob.fx_detail_flag1) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 128.0f,
                    camera_offset_y + projectile->pos.pos_y - 128.0f,
                    256.0f,
                    256.0f);
            }
        } else if (type_id == PROJECTILE_TYPE_SPIDER_PLASMA) {
            float dx = projectile->pos.origin_x - projectile->pos_x;
            float dy = projectile->pos.tail.origin_y
                - projectile->pos.pos_y;
            int distance_i = (int)sqrt(dx * dx + dy * dy);
            int divisor_i = (int)(
                projectile->pos.tail.vy.speed_scale * 2.1f);
            int segment_count = distance_i / divisor_i;
            if (segment_count > 3) {
                segment_count = 3;
            }

            float heading = projectile->angle + 1.5707964f;
            float step_x = (float)cos(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.1f;
            float step_y = (float)sin(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.1f;
            grim_interface_ptr->grim_set_color(
                0.3f, 1.0f, 0.3f, transition_alpha * 0.4f);
            for (int segment_index = 0;
                 segment_index < segment_count;
                 ++segment_index) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x
                        + (float)segment_index * step_x
                        - 6.0f,
                    camera_offset_y + projectile->pos.pos_y
                        + (float)segment_index * step_y
                        - 6.0f,
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
            if (config_blob.fx_detail_flag1) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 60.0f,
                    camera_offset_y + projectile->pos.pos_y - 60.0f,
                    120.0f,
                    120.0f);
            }
        } else {
            float dx = projectile->pos.origin_x - projectile->pos_x;
            float dy = projectile->pos.tail.origin_y
                - projectile->pos.pos_y;
            int distance_i = (int)sqrt(dx * dx + dy * dy);
            int divisor_i = (int)(
                projectile->pos.tail.vy.speed_scale * 2.1f);
            int segment_count = distance_i / divisor_i;
            if (segment_count > 3) {
                segment_count = 3;
            }

            float heading = projectile->angle + 1.5707964f;
            float step_x = (float)cos(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.1f;
            float step_y = (float)sin(heading)
                * projectile->pos.tail.vy.speed_scale
                * 2.1f;
            grim_interface_ptr->grim_set_color(
                0.3f, 0.3f, 1.0f, transition_alpha * 0.4f);
            for (int segment_index = 0;
                 segment_index < segment_count;
                 ++segment_index) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x
                        + (float)segment_index * step_x
                        - 6.0f,
                    camera_offset_y + projectile->pos.pos_y
                        + (float)segment_index * step_y
                        - 6.0f,
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
            if (config_blob.fx_detail_flag1) {
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x - 60.0f,
                    camera_offset_y + projectile->pos.pos_y - 60.0f,
                    120.0f,
                    120.0f);
            }
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
        if (!projectile->active) {
            continue;
        }
        projectile_type_id_t type_id = projectile->pos.tail.vy.type_id;
        float life = projectile->pos.tail.vy.life_timer;

        if (type_id == PROJECTILE_TYPE_PULSE_GUN) {
            grim_interface_ptr->grim_set_rotation(projectile->angle);
            grim_interface_ptr->grim_set_atlas_frame(2, 0);
            if (life == 0.4f) {
                float dx = projectile->pos.tail.vel_x;
                float dy = projectile->pos.tail.vy.vel_y;
                float pulse_scale = (float)sqrt(dx * dx + dy * dy) * 0.01f;
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

        if (type_id == PROJECTILE_TYPE_SPLITTER_GUN
            || type_id == PROJECTILE_TYPE_BLADE_GUN) {
            if (life != 0.4f) {
                continue;
            }
            float dx = projectile->pos.tail.vel_x;
            float dy = projectile->pos.tail.vy.vel_y;
            float size = (float)sqrt(dx * dx + dy * dy);
            if (size > 20.0f) {
                size = 20.0f;
            }
            if (type_id == PROJECTILE_TYPE_SPLITTER_GUN) {
                grim_interface_ptr->grim_set_rotation(projectile->angle);
                grim_interface_ptr->grim_set_atlas_frame(4, 3);
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, transition_alpha);
            } else {
                grim_interface_ptr->grim_set_rotation(
                    (float)projectile_index * 0.1f
                    - (float)quest_spawn_timeline * 0.1f);
                grim_interface_ptr->grim_set_atlas_frame(4, 6);
                grim_interface_ptr->grim_set_color(
                    0.8f, 0.8f, 0.8f, transition_alpha);
            }
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

        if (life == 0.4f) {
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
            vec2f_t direction;
            direction.x = projectile->pos.origin_x - projectile->pos_x;
            direction.y = projectile->pos.tail.origin_y
                - projectile->pos.pos_y;
            float distance = (float)sqrt(
                direction.x * direction.x
                + direction.y * direction.y);
            vec2_normalize_dispatch(&direction, &direction);
            if (type_id == PROJECTILE_TYPE_FIRE_BULLETS) {
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

            vec2f_t direction;
            direction.x = projectile->pos.origin_x - projectile->pos_x;
            direction.y = projectile->pos.tail.origin_y
                - projectile->pos.pos_y;
            float distance = (float)sqrt(
                direction.x * direction.x
                + direction.y * direction.y);
            vec2_normalize_dispatch(&direction, &direction);

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
                    grim_interface_ptr->grim_set_uv_point(0, 0.6f, 0.0f);
                    grim_interface_ptr->grim_set_uv_point(1, 0.6f, 0.25f);
                    grim_interface_ptr->grim_set_uv_point(2, 0.6f, 0.25f);
                    grim_interface_ptr->grim_set_uv_point(3, 0.6f, 0.0f);

                    vec2f_t arc;
                    arc.x = creature_pool[creature_index].pos_x
                        - projectile->pos_x;
                    arc.y = creature_pool[creature_index].pos_y
                        - projectile->pos.pos_y;
                    vec2_normalize_dispatch(&arc, &arc);
                    float side_x = -arc.y * effect_scale;
                    float side_y = arc.x * effect_scale;
                    float start_x = camera_offset_x + projectile->pos_x;
                    float start_y = camera_offset_y
                        + projectile->pos.pos_y;
                    float end_x = camera_offset_x
                        + creature_pool[creature_index].pos_x;
                    float end_y = camera_offset_y
                        + creature_pool[creature_index].pos_y;

                    grim_interface_ptr->grim_draw_quad_points(
                        start_x - side_x * 10.0f,
                        start_y - side_y * 10.0f,
                        start_x + side_x * 10.0f,
                        start_y + side_y * 10.0f,
                        end_x + side_x * 10.0f,
                        end_y + side_y * 10.0f,
                        end_x - side_x * 10.0f,
                        end_y - side_y * 10.0f);
                    grim_interface_ptr->grim_draw_quad_points(
                        start_x - side_x * 14.0f,
                        start_y - side_y * 14.0f,
                        start_x + side_x * 14.0f,
                        start_y + side_y * 14.0f,
                        end_x + side_x * 14.0f,
                        end_y + side_y * 14.0f,
                        end_x - side_x * 14.0f,
                        end_y - side_y * 14.0f);
                    grim_interface_ptr->grim_set_atlas_frame(4, 2);
                    grim_interface_ptr->grim_draw_quad(
                        end_x - effect_scale * 16.0f,
                        end_y - effect_scale * 16.0f,
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

    grim_interface_ptr->grim_set_config_var(0x13, 1u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_begin_batch();
    float plague_phase =
        (float)highscore_active_record.survival_elapsed_ms
        * 0.001f
        * 9.0f;
    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        if (!projectile->active
            || projectile->pos.tail.vy.type_id
                != PROJECTILE_TYPE_PLAGUE_SPREADER) {
            continue;
        }

        float life = projectile->pos.tail.vy.life_timer;
        if (life == 0.4f) {
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
                    + (float)cos(heading) * 15.0f
                    - 30.0f,
                camera_offset_y + projectile->pos.pos_y
                    + (float)sin(heading) * 15.0f
                    - 30.0f,
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
            float fade = projectile_render_clamp(life * 2.5f);
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
    for (projectile_index = 0;
         projectile_index < 0x60;
         ++projectile_index) {
        projectile_t *projectile = &projectile_pool[projectile_index];
        if (projectile->active
            && projectile->pos.tail.vy.type_id
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
        projectile_type_id_t type_id = projectile->pos.tail.vy.type_id;
        if (!projectile->active
            || projectile->pos.tail.vy.life_timer != 0.4f
            || type_id == PROJECTILE_TYPE_PLASMA_RIFLE
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

    if (config_blob.fx_detail_flag1) {
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
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + projectile->pos_x
                        - (float)cos(heading) * 5.0f
                        - 70.0f,
                    camera_offset_y + projectile->pos.pos_y
                        - (float)sin(heading) * 5.0f
                        - 70.0f,
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
        secondary_projectile_type_id_t type_id =
            projectile->pos.vx.vy.type_id;
        if (!projectile->active
            || type_id == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
            continue;
        }
        grim_interface_ptr->grim_set_rotation(projectile->angle);
        switch (type_id) {
        case SECONDARY_PROJECTILE_TYPE_ROCKET:
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 7.0f,
                camera_offset_y + projectile->pos.pos_y - 7.0f,
                14.0f,
                14.0f);
            break;
        case SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET:
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 5.0f,
                camera_offset_y + projectile->pos.pos_y - 5.0f,
                10.0f,
                10.0f);
            break;
        case SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN:
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x - 4.0f,
                camera_offset_y + projectile->pos.pos_y - 4.0f,
                8.0f,
                8.0f);
            break;
        }
    }
    grim_interface_ptr->grim_end_batch();

    if (!config_blob.fx_detail_flag1) {
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
        switch (type_id) {
        case SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN: {
            grim_interface_ptr->grim_set_color(
                0.7f, 0.7f, 1.0f, transition_alpha * 0.158f);
            float heading = projectile->angle - 1.5707964f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x
                    - (float)cos(heading) * 9.0f
                    - 15.0f,
                camera_offset_y + projectile->pos.pos_y
                    - (float)sin(heading) * 9.0f
                    - 15.0f,
                30.0f,
                30.0f);
            break;
        }
        case SECONDARY_PROJECTILE_TYPE_ROCKET: {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha * 0.68f);
            float heading = projectile->angle - 1.5707964f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x
                    - (float)cos(heading) * 9.0f
                    - 30.0f,
                camera_offset_y + projectile->pos.pos_y
                    - (float)sin(heading) * 9.0f
                    - 30.0f,
                60.0f,
                60.0f);
            break;
        }
        case SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET: {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, transition_alpha * 0.58f);
            float heading = projectile->angle - 1.5707964f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + projectile->pos_x
                    - (float)cos(heading) * 9.0f
                    - 20.0f,
                camera_offset_y + projectile->pos.pos_y
                    - (float)sin(heading) * 9.0f
                    - 20.0f,
                40.0f,
                40.0f);
            break;
        }
        }
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
}
