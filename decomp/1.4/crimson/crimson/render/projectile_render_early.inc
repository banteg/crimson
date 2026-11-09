// Native projectile renderer in Crimsonland 1.0.2 (0x4037b0) and 1.4.0 (0x40b570).
#include <math.h>
#include "crimsonland_types.h"
#include "grim2d_cpp.h"
#include "freeware_edition.h"

struct TrailPoint {
    float x, y;
    __forceinline TrailPoint() {}

    __forceinline TrailPoint(const float &x_value, const float &y_value) : x(x_value), y(y_value) {}

    __forceinline TrailPoint operator+(const TrailPoint &other) const { return TrailPoint(x + other.x, y + other.y); }

    __forceinline TrailPoint operator-(const TrailPoint &other) const { return TrailPoint(x - other.x, y - other.y); }

    __forceinline TrailPoint operator-(float value) const { return TrailPoint(x - value, y - value); }

    __forceinline TrailPoint operator*(const float &scale) const { return TrailPoint(x * scale, y * scale); }

    __forceinline TrailPoint operator+=(TrailPoint delta) {
        x += delta.x;
        y += delta.y;
        TrailPoint result;
        result.x = x;
        result.y = y;
        return TrailPoint(result);
    }

    __forceinline float length() const { return (float)sqrt(x * x + y * y); }
};

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int freeware_bullet_texture, freeware_bullet_icon, freeware_particle_texture, current_player_index;
extern projectile_pool_t projectile_pool;
#if CL_BUILD == 10400
extern int config_player_count, perk_id_sharpshooter;
extern secondary_projectile_pool_t secondary_projectile_pool;
#endif
extern float bonus_fire_bullets_timer;
extern unsigned char freeware_glow;
extern TrailPoint freeware_camera, freeware_aim_screen;
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
extern float freeware_elapsed_seconds;
#define TRAIL_PLAYER(i) player_state_table[i].freeware
#define TRAIL_BIND(handle) grim_interface_ptr->grim_bind_texture(handle, 0)
#else
extern freeware_player_t player_state_table[2];
#define TRAIL_PLAYER(i) player_state_table[i]
#define TRAIL_BIND(handle) grim_interface_ptr->grim_bind_texture(handle)
#endif
}
#define TRAIL_POINT(value) reinterpret_cast<const TrailPoint &>(value)

// VC6 builds each offset at the corner where it is used.
#define TRAIL_CORNERS(offset)                                                                                          \
    corner0 = (freeware_camera + TRAIL_POINT(projectile->fields.origin)) - offset;                                     \
    corner1 = (freeware_camera + TRAIL_POINT(projectile->fields.origin)) + offset;                                     \
    corner2 = (freeware_camera + TRAIL_POINT(projectile->position)) + offset;                                          \
    corner3 = (freeware_camera + TRAIL_POINT(projectile->position)) - offset

enum { trail_source_blend = CL_BUILD == 10002 ? 13 : 19, trail_destination_blend = trail_source_blend + 1 };

extern "C" void projectile_render() {
#if CL_BUILD == 10400
    float fade;
#endif
    int i, segment;
    float step_x, step_y;
    TrailPoint corner0, corner1, corner2, corner3;
#if CL_BUILD == 10002
    grim_interface_ptr->grim_set_color_slot(0, .6f, .6f, .6f, 0);
    grim_interface_ptr->grim_set_color_slot(1, .6f, .6f, .6f, 0);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    TRAIL_BIND(freeware_bullet_texture);
#else
    effect_color_t color;
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    TRAIL_BIND(freeware_bullet_texture);
    grim_interface_ptr->grim_set_color(1, 0, 0, .5f);
    grim_interface_ptr->grim_set_color_slot(2, 0, 0, 0, .2f);
    grim_interface_ptr->grim_set_color_slot(3, 0, 0, 0, .2f);
    for (int player_index = 0; player_index < config_player_count; ++player_index) {
        freeware_player_t *player = &TRAIL_PLAYER(player_index);
        const float *aim = &player->aim_heading;
        if (player->health > 0) {
            float heading = (*aim - 1.57079637f);
            TrailPoint direction((float)cos(heading), (float)sin(heading));
            TrailPoint far_pos = TRAIL_POINT(player->position) + direction * 512.f;
            float muzzle_heading = (heading - .150915f);
            TrailPoint start = TRAIL_POINT(player->position);
            start += TrailPoint(((float)cos(muzzle_heading) * 15.f), (float)sin(muzzle_heading) * 15.f);
            TrailPoint half_width((float)cos(*aim) * 1.1f, (float)sin(*aim) * 1.1f);
            corner0 = (freeware_camera + start) - half_width;
            corner1 = (freeware_camera + start) + half_width;
            corner2 = (freeware_camera + far_pos) + half_width;
            corner3 = (freeware_camera + far_pos) - half_width;
            if (TRAIL_PLAYER(0).perks[perk_id_sharpshooter] > 0) {
                grim_interface_ptr->grim_set_config_var(trail_destination_blend, 2u);
                grim_interface_ptr->grim_begin_batch();
                grim_interface_ptr->grim_draw_quad_points(corner0.x, corner0.y, corner1.x, corner1.y, corner2.x,
                                                          corner2.y, corner3.x, corner3.y);
                grim_interface_ptr->grim_end_batch();
                grim_interface_ptr->grim_set_config_var(trail_destination_blend, 6u);
            }
        }
    }
    grim_interface_ptr->grim_set_color_slot(0, .6f, .6f, .6f, 0);
    grim_interface_ptr->grim_set_color_slot(1, .6f, .6f, .6f, 0);
#endif
    grim_interface_ptr->grim_begin_batch();
    // Fire Bullets widens conventional trails and uses additive blending.
    if (bonus_fire_bullets_timer > 0.0f) {
        TRAIL_BIND(freeware_particle_texture);
        grim_interface_ptr->grim_set_config_var(trail_source_blend, 5u);
        grim_interface_ptr->grim_set_config_var(trail_destination_blend, 2u);
        for (i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
            projectile_t *projectile = &projectile_pool[i];
            projectile_vel_y_block_t *tail = &projectile->pos.tail.vy;
            if (!projectile->active || tail->type_id == freeware_rules::plasma_round ||
                tail->type_id == freeware_rules::plasma_minigun_round)
                continue;
            if (tail->type_id == 0)
                projectile->active = 0;
#if CL_BUILD == 10002
            effect_color_t color;
#endif
            color.a = tail->life_timer;
            if (color.a > 1.0f)
                color.a = 1.0f;
            else if (color.a < 0.0f)
                color.a = 0.0f;
            grim_interface_ptr->grim_set_color_slot(2, .8f, .6f, .6f, color.a);
            grim_interface_ptr->grim_set_color_slot(3, .8f, .6f, .6f, color.a);
            if (tail->type_id == 1) {
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * 3.0f));
            } else if (tail->type_id == 4) {
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * (CL_BUILD == 10002 ? 4.0f : 3.0f)));
            } else {
                TRAIL_CORNERS(TrailPoint(projectile->fields.velocity.x * 1.0f, projectile->fields.velocity.y * 1.0f));
            }
            grim_interface_ptr->grim_draw_quad_points(corner0.x, corner0.y, corner1.x, corner1.y, corner2.x, corner2.y,
                                                      corner3.x, corner3.y);
        }
    } else {
        TRAIL_BIND(freeware_bullet_texture);
        for (i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
            projectile_t *projectile = &projectile_pool[i];
            projectile_vel_y_block_t *tail = &projectile->pos.tail.vy;
            if (!projectile->active || projectile->fields.type_id == freeware_rules::plasma_round ||
                projectile->fields.type_id == freeware_rules::plasma_minigun_round ||
                (CL_BUILD == 10400 && (projectile->fields.type_id == 18 || projectile->fields.type_id == 17)))
                continue;
            if (projectile->fields.type_id == 0)
                projectile->active = 0;
#if CL_BUILD == 10002
            effect_color_t color;
#endif
            color.a = tail->life_timer;
            if (color.a > 1.0f)
                color.a = 1.0f;
            else if (color.a < 0.0f)
                color.a = 0.0f;
            grim_interface_ptr->grim_set_color_slot(2, .8f, .6f, .6f, color.a);
            grim_interface_ptr->grim_set_color_slot(3, .8f, .6f, .6f, color.a);
            if (projectile->fields.type_id == 1) {
                TRAIL_CORNERS(TRAIL_POINT(projectile->fields.velocity));
            } else if (projectile->fields.type_id == 4) {
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * (CL_BUILD == 10002 ? 1.5f : 1.3f)));
#if CL_BUILD == 10400
            } else if (projectile->fields.type_id == 10) {
                grim_interface_ptr->grim_set_color_slot(2, .2f, .5f, 1, color.a);
                grim_interface_ptr->grim_set_color_slot(3, .2f, .5f, 1, color.a);
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * 1.2f));
#endif
            } else {
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * 0.7f));
            }
            grim_interface_ptr->grim_draw_quad_points(corner0.x, corner0.y, corner1.x, corner1.y, corner2.x, corner2.y,
                                                      corner3.x, corner3.y);
        }
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(trail_source_blend, 5u);
    grim_interface_ptr->grim_set_config_var(trail_destination_blend, 2u);
    TRAIL_BIND(freeware_particle_texture);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_rotation(0);

    if (TRAIL_PLAYER(current_player_index).muzzle_flash > 0.0f) {
#if CL_BUILD == 10002
        // 1.0.2 derives the muzzle direction from the on-screen aim point.
        const TrailPoint pos =
            TRAIL_POINT(TRAIL_PLAYER(current_player_index).position) - freeware_aim_screen + freeware_camera;
        float heading = (float)atan2(pos.y, pos.x) - 1.57079637f - 1.57079637f - .150915f;
#else
        float heading = TRAIL_PLAYER(current_player_index).aim_heading - 1.57079637f - .150915f;
#endif
        TrailPoint flash((float)cos(heading) * 15.f, (float)sin(heading) * 15.f);
        grim_interface_ptr->grim_set_color(1, 1, 1, TRAIL_PLAYER(current_player_index).muzzle_flash);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            flash.x + TRAIL_PLAYER(current_player_index).position.x + freeware_camera.x - 80,
            flash.y + TRAIL_PLAYER(current_player_index).position.y + freeware_camera.y - 80, 160, 160);
        grim_interface_ptr->grim_end_batch();
    }
    grim_interface_ptr->grim_begin_batch();
    for (i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
        const vec2f_t *pos = &projectile_pool[i].position;
        if (!projectile_pool[i].active || (projectile_pool[i].fields.type_id != freeware_rules::plasma_round &&
                                           projectile_pool[i].fields.type_id != freeware_rules::plasma_minigun_round))
            continue;
        if (projectile_pool[i].fields.life_timer == .4f) {
            if (projectile_pool[i].fields.type_id == freeware_rules::plasma_round) {
#if CL_BUILD == 10400
                float dx = projectile_pool[i].fields.origin.x - pos->x;
                float dy = projectile_pool[i].fields.origin.y - pos->y;
                float dx_squared = dx * dx;
                float length = (float)sqrt(dx_squared + dy * dy);
                int distance = (int)length;
#else
                TrailPoint span = TRAIL_POINT(projectile_pool[i].fields.origin) - TRAIL_POINT(*pos);
                int distance = (int)span.length();
#endif
                int gap = (int)(projectile_pool[i].fields.speed_scale * 2.5f);
                int count = distance / gap;
                if (count > 8)
                    count = 8;
                float heading = projectile_pool[i].angle + 1.57079637f;
                step_x = (float)cos(heading) * projectile_pool[i].fields.speed_scale * 2.5f;
                step_y = (float)sin(heading) * projectile_pool[i].fields.speed_scale * 2.5f;
                grim_interface_ptr->grim_set_color(1, 1, 1, .4f);
                for (segment = 0; segment < count; ++segment) {
#if CL_BUILD == 10002
                    grim_interface_ptr->grim_draw_quad(segment * step_x + pos->x + freeware_camera.x - 11,
                                                       segment * step_y + pos->y + freeware_camera.y - 11, 22, 22);
#else
                    float index = (float)segment;
                    grim_interface_ptr->grim_draw_quad(index * step_x + pos->x + freeware_camera.x - 11,
                                                       (index * step_y + freeware_camera.y) + pos->y - 11, 22, 22);
#endif
                }
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.45f);
                grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 28, freeware_camera.y + pos->y - 28, 56,
                                                   56);
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.3f);
                if (freeware_glow)
                    grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 128,
                                                       freeware_camera.y + pos->y - 128, 256, 256);
            } else if (projectile_pool[i].fields.type_id == freeware_rules::plasma_minigun_round) {
#if CL_BUILD == 10400
                float dx = projectile_pool[i].fields.origin.x - pos->x;
                float dy = projectile_pool[i].fields.origin.y - pos->y;
                float dx_squared = dx * dx;
                float length = (float)sqrt(dx_squared + dy * dy);
                int distance = (int)length;
#else
                TrailPoint span = TRAIL_POINT(projectile_pool[i].fields.origin) - TRAIL_POINT(*pos);
                int distance = (int)span.length();
#endif
                int gap = (int)(projectile_pool[i].fields.speed_scale * 2.1f);
                int count = distance / gap;
                if (count > 3)
                    count = 3;
                float heading = projectile_pool[i].angle + 1.57079637f;
                step_x = (float)cos(heading) * projectile_pool[i].fields.speed_scale * 2.1f;
                step_y = (float)sin(heading) * projectile_pool[i].fields.speed_scale * 2.1f;
                grim_interface_ptr->grim_set_color(1, 1, 1, .4f);
                for (segment = 0; segment < count; ++segment) {
#if CL_BUILD == 10002
                    grim_interface_ptr->grim_draw_quad(segment * step_x + pos->x + freeware_camera.x - 6,
                                                       segment * step_y + pos->y + freeware_camera.y - 6, 12, 12);
#else
                    float index = (float)segment;
                    grim_interface_ptr->grim_draw_quad(index * step_x + pos->x + freeware_camera.x - 6,
                                                       (index * step_y + freeware_camera.y) + pos->y - 6, 12, 12);
#endif
                }
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.5f);
                grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 8, freeware_camera.y + pos->y - 8, 16,
                                                   16);
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.15f);
                if (freeware_glow)
                    grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 60, freeware_camera.y + pos->y - 60,
                                                       120, 120);
            }
        } else {
#if CL_BUILD == 10400
            fade = projectile_pool[i].fields.life_timer * 2.5f;
            if (fade > 1.f)
                fade = 1.f;
            else if (fade < 0.f)
                fade = 0.f;
            grim_interface_ptr->grim_set_color(1, 1, 1, fade);
#else
            grim_interface_ptr->grim_set_color(1, 1, 1, projectile_pool[i].fields.life_timer * 2.5f);
#endif
            grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 28, freeware_camera.y + pos->y - 28, 56,
                                               56);
        }
    }
    grim_interface_ptr->grim_end_batch();

#if CL_BUILD == 10400
    // Ion and plague rounds draw orbiting glow sprites before their fading halos.
    TRAIL_BIND(grim_interface_ptr->grim_get_texture_handle("glow"));
    grim_interface_ptr->grim_begin_batch();
    for (i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
        const projectile_t &projectile = projectile_pool[i];
        if (!projectile.active || projectile.fields.type_id != 18)
            continue;
        if (projectile.fields.life_timer == .4f) {
            grim_interface_ptr->grim_set_color(1, 1, 1, 1);
            grim_interface_ptr->grim_draw_quad(freeware_camera.x + projectile.pos_x - 30,
                                               freeware_camera.y + projectile.position.y - 30, 60, 60);
            grim_interface_ptr->grim_set_color(1, .2f, .2f, .9f);
            float phase = freeware_elapsed_seconds * 9.f + (float)i;
            grim_interface_ptr->grim_draw_quad(
                ((freeware_camera.x + projectile.pos_x) - 21) + ((float)cos(phase) * 13.f),
                ((freeware_camera.y + projectile.position.y) - 21) + ((float)sin(phase) * 13.f), 42, 42);
            grim_interface_ptr->grim_set_color(.2f, 1, .2f, .9f);
            float phase_120 = freeware_elapsed_seconds * 9.f + (float)i + 2.0943952f;
            grim_interface_ptr->grim_draw_quad(
                freeware_camera.x + projectile.pos_x - 21 + (float)cos(phase_120) * 13,
                freeware_camera.y + projectile.position.y - 21 + (float)sin(phase_120) * 13, 42, 42);
            grim_interface_ptr->grim_set_color(.2f, .2f, 1, .9f);
            float phase_240 = freeware_elapsed_seconds * 9.f + (float)i + 4.1887903f;
            grim_interface_ptr->grim_draw_quad(
                freeware_camera.x + projectile.pos_x - 21 + (float)cos(phase_240) * 13,
                freeware_camera.y + projectile.position.y - 21 + (float)sin(phase_240) * 13, 42, 42);
        } else {
            fade = projectile.fields.life_timer * 2.5f;
            if (fade > 1.f)
                fade = 1.f;
            else if (fade < 0.f)
                fade = 0.f;
            grim_interface_ptr->grim_set_color(1, 1, 1, fade);
            grim_interface_ptr->grim_draw_quad(freeware_camera.x + projectile.pos_x - (fade * 40.f + 38.f),
                                               freeware_camera.y + projectile.position.y - (fade * 40.f + 38.f),
                                               fade * 80.f + 76.f, fade * 80.f + 76.f);
        }
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(19, 1u);
    grim_interface_ptr->grim_set_config_var(20, 6u);
    grim_interface_ptr->grim_begin_batch();
    for (i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
        const projectile_t &projectile = projectile_pool[i];
        if (!projectile.active || projectile.fields.type_id != 17)
            continue;
        if (projectile.fields.life_timer == .4f) {
            grim_interface_ptr->grim_set_color(1, 1, 1, 1);
            grim_interface_ptr->grim_draw_quad(freeware_camera.x + projectile.pos_x - 30,
                                               freeware_camera.y + projectile.position.y - 30, 60, 60);
            float heading = projectile.angle + 1.57079637f;
            grim_interface_ptr->grim_draw_quad(
                freeware_camera.x + projectile.pos_x - 30 + (float)cos(heading) * 15,
                freeware_camera.y + projectile.position.y - 30 + (float)sin(heading) * 15, 60, 60);
            grim_interface_ptr->grim_set_color(1, 1, 1, 1);
            float phase = freeware_elapsed_seconds * 9.f + (float)i;
            float phase_cos = (float)cos(phase);
            grim_interface_ptr->grim_draw_quad(freeware_camera.x + projectile.pos_x - 31 + phase_cos * phase_cos,
                                               freeware_camera.y + projectile.position.y - 31 + (float)sin(phase) * 11,
                                               52, 52);
            grim_interface_ptr->grim_set_color(1, 1, 1, 1);
            float phase_120 = freeware_elapsed_seconds * 9.f + (float)i + 2.0943952f;
            grim_interface_ptr->grim_draw_quad(
                freeware_camera.x + projectile.pos_x - 31 + (float)cos(phase_120) * 10,
                freeware_camera.y + projectile.position.y - 31 + (float)sin(phase_120) * 10, 62, 62);
            grim_interface_ptr->grim_set_color(1, 1, 1, 1);
            float phase_240 = freeware_elapsed_seconds * 9.f + (float)i + 4.1887903f;
            grim_interface_ptr->grim_draw_quad(
                freeware_camera.x + projectile.pos_x - 31 + (float)cos(phase_240) * 10,
                freeware_camera.y + projectile.position.y - 31 +
                    (float)sin(phase_240) * (float)sin(freeware_elapsed_seconds * 9.f + (float)i + 2.0943952f),
                62, 62);
        } else {
            fade = projectile.fields.life_timer * 2.5f;
            if (fade > 1.f)
                fade = 1.f;
            else if (fade < 0.f)
                fade = 0.f;
            grim_interface_ptr->grim_set_color(1, 1, 1, fade);
            grim_interface_ptr->grim_draw_quad(freeware_camera.x + projectile.pos_x - (fade * 20.f + 16.f),
                                               freeware_camera.y + projectile.position.y - (fade * 20.f + 16.f),
                                               fade * 40.f + 32.f, fade * 40.f + 32.f);
        }
    }
    grim_interface_ptr->grim_end_batch();
#endif

    if (bonus_fire_bullets_timer > 0.0f) {
        grim_interface_ptr->grim_set_config_var(trail_source_blend, 5u);
        grim_interface_ptr->grim_set_config_var(trail_destination_blend, 2u);
        TRAIL_BIND(freeware_particle_texture);
        float a = bonus_fire_bullets_timer * .25f;
        if (a < 1.f)
            grim_interface_ptr->grim_set_color(1, 1, 1, a);
        else
            grim_interface_ptr->grim_set_color(1, 1, 1, 1.f);
        grim_interface_ptr->grim_begin_batch();
        for (i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
            if (!projectile_pool[i].active || projectile_pool[i].fields.life_timer != .4f)
                continue;
            grim_interface_ptr->grim_set_rotation(projectile_pool[i].angle);
            TrailPoint pos = freeware_camera + TRAIL_POINT(projectile_pool[i].position) - 32.f;
            grim_interface_ptr->grim_draw_quad(pos.x, pos.y, 64, 64);
        }
        grim_interface_ptr->grim_end_batch();
    }
    grim_interface_ptr->grim_set_config_var(trail_source_blend, 5u);
    grim_interface_ptr->grim_set_config_var(trail_destination_blend, 6u);
    grim_interface_ptr->grim_set_color(.8f, .8f, .8f, .9f);
    TRAIL_BIND(freeware_bullet_icon);
    grim_interface_ptr->grim_begin_batch();
    for (int j = 0; j < PROJECTILE_POOL_CAPACITY; ++j) {
        const projectile_t &projectile = projectile_pool[j];
        if (!projectile.active || projectile.fields.life_timer != .4f ||
            projectile.fields.type_id == freeware_rules::plasma_round ||
            projectile.fields.type_id == freeware_rules::plasma_minigun_round)
            continue;
        grim_interface_ptr->grim_set_rotation(projectile.angle);
        if (projectile.fields.type_id == 1) {
            TrailPoint pos = freeware_camera + TRAIL_POINT(projectile.position) - 3.f;
            grim_interface_ptr->grim_draw_quad(pos.x, pos.y, 6, 6);
        } else if (projectile.fields.type_id == 4) {
            TrailPoint pos = freeware_camera + TRAIL_POINT(projectile.position) - 4.f;
            grim_interface_ptr->grim_draw_quad(pos.x, pos.y, 8, 8);
        } else {
            TrailPoint pos = freeware_camera + TRAIL_POINT(projectile.position) - 2.f;
            grim_interface_ptr->grim_draw_quad(pos.x, pos.y, 4, 4);
        }
    }
    grim_interface_ptr->grim_end_batch();
#if CL_BUILD == 10400
    int secondary_index;
    if (freeware_glow) {
        grim_interface_ptr->grim_set_config_var(trail_source_blend, 5u);
        grim_interface_ptr->grim_set_config_var(trail_destination_blend, 2u);
        TRAIL_BIND(freeware_particle_texture);
        grim_interface_ptr->grim_begin_batch();
        for (secondary_index = 0; secondary_index < 0x40; ++secondary_index) {
            secondary_projectile_t *projectile = &secondary_projectile_pool[secondary_index];
            if (projectile->active) {
                grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.48f);
                float heading = projectile->angle - 1.5707964f;
                TrailPoint draw_pos = freeware_camera + TRAIL_POINT(projectile->position) -
                                      TrailPoint((float)cos(heading), (float)sin(heading)) * 5.0f - 70.0f;
                grim_interface_ptr->grim_draw_quad(draw_pos.x, draw_pos.y, 140.0f, 140.0f);
            }
        }
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(trail_destination_blend, 6u);
    }

    grim_interface_ptr->grim_set_config_var(trail_source_blend, 5u);
    grim_interface_ptr->grim_set_config_var(trail_destination_blend, 6u);
    grim_interface_ptr->grim_set_color(0.8f, 0.8f, 0.8f, 0.9f);
    TRAIL_BIND(grim_interface_ptr->grim_get_texture_handle("rocket"));
    grim_interface_ptr->grim_begin_batch();
    for (secondary_index = 0; secondary_index < 0x40; ++secondary_index) {
        if (!secondary_projectile_pool[secondary_index].active ||
            secondary_projectile_pool[secondary_index].fields.type_id == 3) {
            continue;
        }
        grim_interface_ptr->grim_set_rotation(secondary_projectile_pool[secondary_index].angle);
        TrailPoint draw_pos = freeware_camera + TRAIL_POINT(secondary_projectile_pool[secondary_index].position) - 5.0f;
        grim_interface_ptr->grim_draw_quad(draw_pos.x, draw_pos.y, 10.0f, 10.0f);
    }
    grim_interface_ptr->grim_end_batch();

    if (!freeware_glow) {
        return;
    }
    grim_interface_ptr->grim_set_config_var(trail_source_blend, 5u);
    grim_interface_ptr->grim_set_config_var(trail_destination_blend, 2u);
    TRAIL_BIND(freeware_particle_texture);
    grim_interface_ptr->grim_begin_batch();
    for (secondary_index = 0; secondary_index < 0x40; ++secondary_index) {
        secondary_projectile_t *projectile = &secondary_projectile_pool[secondary_index];
        if (!projectile->active) {
            continue;
        }
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.68f);
        float heading = projectile->angle - 1.5707964f;
        TrailPoint draw_pos = freeware_camera + TRAIL_POINT(projectile->position) -
                              TrailPoint((float)cos(heading), (float)sin(heading)) * 9.0f - 30.0f;
        grim_interface_ptr->grim_draw_quad(draw_pos.x, draw_pos.y, 60.0f, 60.0f);
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(trail_destination_blend, 6u);
#endif
}

#undef TRAIL_CORNERS
#undef TRAIL_POINT
#undef TRAIL_BIND
#undef TRAIL_PLAYER
