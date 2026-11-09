// Crimsonland 1.0.2, 0x4037b0..0x404ab7.
#include <math.h>
#include "crimsonland_types.h"
#include "grim2d_cpp.h"
#include "freeware_edition.h"

struct TrailPoint {
    float x, y;
    __forceinline TrailPoint() {}

    __forceinline TrailPoint(const float &x_value, const float &y_value) : x(x_value), y(y_value) {}

    __forceinline TrailPoint operator+(const TrailPoint &other) const {
        return TrailPoint(x + other.x, y + other.y);
    }

    __forceinline TrailPoint operator-(const TrailPoint &other) const {
        return TrailPoint(x - other.x, y - other.y);
    }

    __forceinline TrailPoint operator-(float value) const { return TrailPoint(x - value, y - value); }

    __forceinline TrailPoint operator*(const float &scale) const { return TrailPoint(x * scale, y * scale); }

    __forceinline float length() const { return (float)sqrt(x * x + y * y); }
};

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int freeware_bullet_texture, freeware_bullet_icon, freeware_particle_texture, current_player_index;
extern projectile_pool_t projectile_pool;
extern float bonus_fire_bullets_timer;
extern unsigned char freeware_glow;
extern TrailPoint freeware_camera, freeware_aim_screen;
extern freeware_player_t player_state_table[2];
}
#define TRAIL_POINT(value) reinterpret_cast<const TrailPoint &>(value)

// VC6 builds each offset at the corner where it is used.
#define TRAIL_CORNERS(offset) \
    corner0 = (freeware_camera + TRAIL_POINT(projectile->fields.origin)) - offset; \
    corner1 = (freeware_camera + TRAIL_POINT(projectile->fields.origin)) + offset; \
    corner2 = (freeware_camera + TRAIL_POINT(projectile->position)) + offset; \
    corner3 = (freeware_camera + TRAIL_POINT(projectile->position)) - offset

extern "C" void projectile_render() {
    int segment;
    float step_x, step_y;
    TrailPoint corner0, corner1, corner2, corner3;
    grim_interface_ptr->grim_set_color_slot(0, .6f, .6f, .6f, 0);
    grim_interface_ptr->grim_set_color_slot(1, .6f, .6f, .6f, 0);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_bind_texture(freeware_bullet_texture);
    grim_interface_ptr->grim_begin_batch();
    // Fire Bullets widens conventional trails and uses additive blending.
    if (bonus_fire_bullets_timer > 0.0f) {
        grim_interface_ptr->grim_bind_texture(freeware_particle_texture);
        grim_interface_ptr->grim_set_config_var(13, 5u);
        grim_interface_ptr->grim_set_config_var(14, 2u);
        for (int i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
            projectile_t *projectile = &projectile_pool[i];
            projectile_vel_y_block_t *tail = &projectile->pos.tail.vy;
            if (!projectile->active || tail->type_id == freeware_rules::plasma_round ||
                tail->type_id == freeware_rules::plasma_minigun_round)
                continue;
            if (tail->type_id == 0)
                projectile->active = 0;
            effect_color_t color;
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
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * 4.0f));
            } else {
                TRAIL_CORNERS(TrailPoint(projectile->fields.velocity.x * 1.0f, projectile->fields.velocity.y * 1.0f));
            }
            grim_interface_ptr->grim_draw_quad_points(corner0.x, corner0.y, corner1.x, corner1.y, corner2.x,
                                                      corner2.y, corner3.x, corner3.y);
        }
    } else {
        grim_interface_ptr->grim_bind_texture(freeware_bullet_texture);
        for (int i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
            projectile_t *projectile = &projectile_pool[i];
            projectile_vel_y_block_t *tail = &projectile->pos.tail.vy;
            if (!projectile->active || tail->type_id == freeware_rules::plasma_round ||
                tail->type_id == freeware_rules::plasma_minigun_round)
                continue;
            if (tail->type_id == 0)
                projectile->active = 0;
            effect_color_t color;
            color.a = tail->life_timer;
            if (color.a > 1.0f)
                color.a = 1.0f;
            else if (color.a < 0.0f)
                color.a = 0.0f;
            grim_interface_ptr->grim_set_color_slot(2, .8f, .6f, .6f, color.a);
            grim_interface_ptr->grim_set_color_slot(3, .8f, .6f, .6f, color.a);
            if (tail->type_id == 1) {
                TRAIL_CORNERS(TRAIL_POINT(projectile->fields.velocity));
            } else if (tail->type_id == 4) {
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * 1.5f));
            } else {
                TRAIL_CORNERS((TRAIL_POINT(projectile->fields.velocity) * 0.7f));
            }
            grim_interface_ptr->grim_draw_quad_points(corner0.x, corner0.y, corner1.x, corner1.y, corner2.x,
                                                      corner2.y, corner3.x, corner3.y);
        }
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(13, 5u);
    grim_interface_ptr->grim_set_config_var(14, 2u);
    grim_interface_ptr->grim_bind_texture(freeware_particle_texture);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_rotation(0);

    // This build derives the muzzle direction from the on-screen aim point.
    if (player_state_table[current_player_index].muzzle_flash > 0.0f) {
        const TrailPoint pos =
            TRAIL_POINT(player_state_table[current_player_index].position) - freeware_aim_screen + freeware_camera;
        float heading = (float)atan2(pos.y, pos.x) - 1.57079637f - 1.57079637f - .150915f;
        TrailPoint flash((float)cos(heading) * 15.f, (float)sin(heading) * 15.f);
        grim_interface_ptr->grim_set_color(1, 1, 1, player_state_table[current_player_index].muzzle_flash);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            flash.x + player_state_table[current_player_index].position.x + freeware_camera.x - 80,
            flash.y + player_state_table[current_player_index].position.y + freeware_camera.y - 80, 160, 160);
        grim_interface_ptr->grim_end_batch();
    }
    grim_interface_ptr->grim_begin_batch();
    for (int i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
        const vec2f_t *pos = &projectile_pool[i].position;
        if (!projectile_pool[i].active ||
            (projectile_pool[i].fields.type_id != freeware_rules::plasma_round &&
             projectile_pool[i].fields.type_id != freeware_rules::plasma_minigun_round))
            continue;
        if (projectile_pool[i].fields.life_timer == .4f) {
            if (projectile_pool[i].fields.type_id == freeware_rules::plasma_round) {
                TrailPoint span = TRAIL_POINT(projectile_pool[i].fields.origin) - TRAIL_POINT(*pos);
                int distance = (int)span.length();
                int gap = (int)(projectile_pool[i].fields.speed_scale * 2.5f);
                int count = distance / gap;
                if (count > 8)
                    count = 8;
                float heading = projectile_pool[i].angle + 1.57079637f;
                step_x = (float)cos(heading) * projectile_pool[i].fields.speed_scale * 2.5f;
                step_y = (float)sin(heading) * projectile_pool[i].fields.speed_scale * 2.5f;
                grim_interface_ptr->grim_set_color(1, 1, 1, .4f);
                for (segment = 0; segment < count; ++segment) {
                    grim_interface_ptr->grim_draw_quad(segment * step_x + pos->x + freeware_camera.x - 11,
                                                       segment * step_y + pos->y + freeware_camera.y - 11, 22, 22);
                }
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.45f);
                grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 28,
                                                   freeware_camera.y + pos->y - 28, 56, 56);
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.3f);
                if (freeware_glow)
                    grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 128,
                                                       freeware_camera.y + pos->y - 128, 256, 256);
            } else if (projectile_pool[i].fields.type_id == freeware_rules::plasma_minigun_round) {
                TrailPoint span = TRAIL_POINT(projectile_pool[i].fields.origin) - TRAIL_POINT(*pos);
                int distance = (int)span.length();
                int gap = (int)(projectile_pool[i].fields.speed_scale * 2.1f);
                int count = distance / gap;
                if (count > 3)
                    count = 3;
                float heading = projectile_pool[i].angle + 1.57079637f;
                step_x = (float)cos(heading) * projectile_pool[i].fields.speed_scale * 2.1f;
                step_y = (float)sin(heading) * projectile_pool[i].fields.speed_scale * 2.1f;
                grim_interface_ptr->grim_set_color(1, 1, 1, .4f);
                for (segment = 0; segment < count; ++segment) {
                    grim_interface_ptr->grim_draw_quad(segment * step_x + pos->x + freeware_camera.x - 6,
                                                       segment * step_y + pos->y + freeware_camera.y - 6, 12, 12);
                }
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.5f);
                grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 8, freeware_camera.y + pos->y - 8,
                                                   16, 16);
                grim_interface_ptr->grim_set_color(1, 1, 1, 0.15f);
                if (freeware_glow)
                    grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 60,
                                                       freeware_camera.y + pos->y - 60, 120, 120);
            }
        } else {
            grim_interface_ptr->grim_set_color(1, 1, 1, projectile_pool[i].fields.life_timer * 2.5f);
            grim_interface_ptr->grim_draw_quad(freeware_camera.x + pos->x - 28, freeware_camera.y + pos->y - 28,
                                               56, 56);
        }
    }
    grim_interface_ptr->grim_end_batch();

    if (bonus_fire_bullets_timer > 0.0f) {
        grim_interface_ptr->grim_set_config_var(13, 5u);
        grim_interface_ptr->grim_set_config_var(14, 2u);
        grim_interface_ptr->grim_bind_texture(freeware_particle_texture);
        float a = bonus_fire_bullets_timer * .25f;
        if (a < 1.f)
            grim_interface_ptr->grim_set_color(1, 1, 1, a);
        else
            grim_interface_ptr->grim_set_color(1, 1, 1, 1.f);
        grim_interface_ptr->grim_begin_batch();
        for (int i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
            if (!projectile_pool[i].active || projectile_pool[i].fields.life_timer != .4f)
                continue;
            grim_interface_ptr->grim_set_rotation(projectile_pool[i].angle);
            TrailPoint pos = freeware_camera + TRAIL_POINT(projectile_pool[i].position) - 32.f;
            grim_interface_ptr->grim_draw_quad(pos.x, pos.y, 64, 64);
        }
        grim_interface_ptr->grim_end_batch();
    }
    grim_interface_ptr->grim_set_config_var(13, 5u);
    grim_interface_ptr->grim_set_config_var(14, 6u);
    grim_interface_ptr->grim_set_color(.8f, .8f, .8f, .9f);
    grim_interface_ptr->grim_bind_texture(freeware_bullet_icon);
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
}

#undef TRAIL_CORNERS
#undef TRAIL_POINT
