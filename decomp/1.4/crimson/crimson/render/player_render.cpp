#include "cl_build.h"

struct RenderPoint {
    float x, y;
    RenderPoint() {}
    RenderPoint(float x, float y) : x(x), y(y) {}
    RenderPoint operator+(const RenderPoint &p) const { return RenderPoint(x + p.x, y + p.y); }
    RenderPoint operator-(const RenderPoint &p) const { return RenderPoint(x - p.x, y - p.y); }
};

#if CL_BUILD == 10002
#include "player_render_early.inc"
#else
// Player shadows, torso and pickups in Crimsonland 1.3.0 and 1.4.0.
#include "world_render.h"
#include "freeware_edition.h"
#include <math.h>
extern "C" {
extern int perk_id_radioactive, perk_id_almost_invisible;
extern float bonus_fire_bullets_timer, bonus_reflex_boost_timer;
extern vec2f_t freeware_camera_shake;
void weapon_assign_player(int, int);
void freeware_refill_clip();
int sfx_play_panned(int, float, float);
}
using namespace world140;
namespace {
#define PLAYER UI_PLAYER(current_player_index)
#define POS UI_FIELD(PLAYER.position, actor(current_player_index).player)
#define SHIELD UI_FIELD(PLAYER.shield, actor(current_player_index).shield)
__forceinline void player_sheet() {
#ifdef CRIMSON_FREEWARE_CLIENT
    bind("ugluk");
#else
    bind(freeware_player_texture);
#endif
}
#define DRAW_POINTS ((RenderPoint *)freeware_draw_point)
#define VIEW (*(const RenderPoint *)&CAMERA)
#define POSITION (*(const RenderPoint *)&POS)
__forceinline void sprite_atlas(int base, int cell) {
#ifdef CRIMSON_FREEWARE_CLIENT
    atlas(base + cell);
#else
    const RenderPoint *table = (const RenderPoint *)freeware_atlas_uv + base;
    RenderPoint origin = table[cell];
    DRAW_POINTS[0] = origin;
    DRAW_POINTS[1] = table[cell] + RenderPoint(.125f, .125f);
    world_uv(DRAW_POINTS[0].x, DRAW_POINTS[0].y, DRAW_POINTS[1].x, DRAW_POINTS[1].y);
#endif
}
__forceinline float visibility() {
    return (float)sin(freeware_simulation_clock) * .35f + .5f;
}
__forceinline void collect() {
    if (PICKUP_ID == freeware_no_pickup || !(PICKUP_TIME > 0.0f))
        return;
    RenderPoint delta = POSITION - *(const RenderPoint *)&PICKUP_POS;
    if (!((float)sqrt(delta.x * delta.x + delta.y * delta.y) < 32.0f))
        return;
    if (PICKUP_ID == freeware_bonus_fire)
        bonus_fire_bullets_timer = 8;
    else if (PICKUP_ID == freeware_bonus_weapon) {
#if FREEWARE_EDITION == 10002
        // 0x40772e draws the weapon when collected. A pistol picked up later has 15 rounds.
        int weapon = crt_rand() % 8 + 1;
        while (weapon == PLAYER.weapon)
            weapon = crt_rand() % 7 + 1;
        weapon_assign_player(current_player_index, weapon);
#else
        weapon_assign_player(current_player_index, PICKUP_WEAPON);
#endif
    } else if (PICKUP_ID == freeware_bonus_freeze)
        UI_FIELD(bonus_freeze_timer, run.freeze) = 5;
    else if (PICKUP_ID == freeware_bonus_nuke) {
        BOMB_AGE = 0;
        BOMB_POS = PICKUP_POS;
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.camera_shake = {10, 10};
#else
        reinterpret_cast<RenderPoint &>(freeware_camera_shake) = RenderPoint(10, 10);
#endif
        sfx_play_panned(21, .45f, .5f);
    } else if (PICKUP_ID == freeware_bonus_shield)
        SHIELD = 6;
    else if (PICKUP_ID == freeware_bonus_time) {
#if FREEWARE_EDITION != 10300
        freeware_refill_clip();
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.actor(current_player_index).cooldown = PLAYER.cooldown;
#endif
        UI_FIELD(bonus_reflex_boost_timer, run.slow) = 4;
#else
        UI_FIELD(bonus_reflex_boost_timer, run.slow) = 2;
#endif
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.run.pickup.kind = static_cast<freeware::Bonus>(freeware_no_pickup);
#else
    freeware_pickup_id = freeware_no_pickup;
#endif
    PICKUP_TIME = 0;
    sfx_play_panned(18, .45f, .5f);
}
} // namespace
extern "C" void player_render() {
    if (!(UI_FIELD(PLAYER.health, actor(current_player_index).health) > 0))
        return;
    if (PLAYER.perks[perk_id_radioactive] > 0) {
        source(5);
        destination(2);
        bind("glow");
        float alpha = (sinf(freeware_simulation_clock) + 1.0f) * .1875f + .25f;
        world_tint(.3f, .6f, .3f, alpha);
        world_uv(0, 0, 1, 1);
        world_angle(0);
        begin();
        float size = alpha + .75f;
        world_quad(CAMERA.x + POS.x - size * 32, CAMERA.y + POS.y - size * 32, size * 64,
                   size * 64);
        end();
    }
    player_sheet();
    source(1);
    destination(6);
    int cell = (int)(PLAYER.walk_phase + .5f);
    float recoil_heading = PLAYER.aim_heading + 1.57079637f;
    RenderPoint offset;
    offset = RenderPoint(cosf(recoil_heading) * PLAYER.muzzle_flash * 12,
                         sinf(recoil_heading) * PLAYER.muzzle_flash * 12);
    if (PLAYER.perks[perk_id_almost_invisible] > 0)
        world_tint(1, 1, 1, ((float)sin(freeware_simulation_clock) * .35f + .5f) * .5f);
    else
        world_tint(1, 1, 1, .35f);
    world_angle(PLAYER.heading);
    sprite_atlas(0, cell);
    begin();
    DRAW_POINTS[0] = VIEW + POSITION - RenderPoint(PLAYER.size * .5f - 2, PLAYER.size * .5f - 2);
    float leg_shadow_size = PLAYER.size * 1.02f;
    world_quad(freeware_draw_point[0].x + 1, freeware_draw_point[0].y + 1, leg_shadow_size,
               leg_shadow_size);
    sprite_atlas(16, cell);
    world_angle(PLAYER.aim_heading);
    DRAW_POINTS[0] = VIEW + POSITION - RenderPoint(PLAYER.size * .5f, PLAYER.size * .5f) + offset;
    float torso_shadow_size = PLAYER.size * 1.03f;
    world_quad(freeware_draw_point[0].x + 1, freeware_draw_point[0].y + 1, torso_shadow_size,
               torso_shadow_size);
    end();
    player_sheet();
    source(5);
    destination(6);
    begin();
    if (PLAYER.perks[perk_id_almost_invisible] > 0)
        world_tint(1, 1, 1, visibility());
    else
        world_tint(1, 1, 1, 1);
    world_angle(PLAYER.heading);
    sprite_atlas(0, cell);
    float body_size = PLAYER.size;
    DRAW_POINTS[0] = VIEW + POSITION - RenderPoint(PLAYER.size * .5f, PLAYER.size * .5f);
    world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, body_size, body_size);
    float alpha = 1;
    if (PLAYER.perks[perk_id_almost_invisible] > 0)
        alpha = visibility();
    world_tint(1, 1, 1, alpha);
    if (config_player_count > 1) {
        if (current_player_index == 0)
            world_tint(.3f, .3f, 1, alpha);
        else
            world_tint(1, .55f, .35f, alpha);
    }
    sprite_atlas(16, cell);
    world_angle(PLAYER.aim_heading);
    body_size = PLAYER.size;
    DRAW_POINTS[0] = VIEW + POSITION - RenderPoint(PLAYER.size * .5f, PLAYER.size * .5f) + offset;
    world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, body_size, body_size);
    end();
    collect();
    if (SHIELD > 0) {
        RenderPoint shield_offset;
        source(5);
        destination(2);
        bind("shockwave");
        float shield_alpha = (float)(((float)sin(freeware_simulation_clock) + 1.0f) * .25 + SHIELD);
        const float &shield_time = SHIELD;
        if (shield_time < 1)
            shield_alpha = shield_time * shield_alpha;
        if (shield_alpha > 1)
            shield_alpha = 1;
        world_tint(91.f / 255, 180.f / 255, 1, shield_alpha * .4f);
        world_uv(0, 0, 1, 1);
        float radius = (float)sin(freeware_simulation_clock * 3) + 17.5f;
        float shield_heading = PLAYER.aim_heading - 1.57079637f;
        shield_offset = RenderPoint((float)cos(shield_heading) * 3, (float)sin(shield_heading) * 3);
        world_angle(freeware_simulation_clock * 2);
        begin();
        world_quad(CAMERA.x + POS.x - radius + shield_offset.x,
                   shield_offset.y + POS.y + CAMERA.y - radius, radius + radius, radius + radius);
        world_tint(91.f / 255, 180.f / 255, 1, shield_alpha * .1f);
        radius = (float)sin(freeware_simulation_clock * 3) + 18.0f;
        world_angle(freeware_simulation_clock * -2);
        world_quad(CAMERA.x + POS.x - radius + shield_offset.x,
                   shield_offset.y + POS.y + CAMERA.y - radius, radius + radius, radius + radius);
        end();
        destination(6);
    }
}
#endif
