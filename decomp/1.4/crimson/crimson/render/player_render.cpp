// crimson.exe 1.4.0, 0x4103b0.
#include "world_render.h"
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
#define PLAYER player_state_table[current_player_index].freeware
#define POS UI_FIELD(PLAYER.position, actor(current_player_index).player)
#define SHIELD UI_FIELD(PLAYER.shield, actor(current_player_index).shield)
__forceinline void player_sheet() {
#ifdef CRIMSON_FREEWARE_CLIENT
    bind("ugluk");
#else
    bind(freeware_player_texture);
#endif
}
__forceinline void upper_left(float inset, float dx, float dy) {
    vec2f_t corner = {CAMERA.x + POS.x - inset + dx, CAMERA.y + POS.y - inset + dy};
    freeware_draw_point[0] = corner;
}
__forceinline float visibility() { return (float)(sin(freeware_simulation_clock) * .35f + .5f); }
__forceinline void collect() {
    if (PICKUP_ID == freeware_no_pickup || PICKUP_TIME <= 0)
        return;
    double x = POS.x - PICKUP_POS.x, y = POS.y - PICKUP_POS.y;
    if (sqrt(x * x + y * y) >= 32)
        return;
    if (PICKUP_ID == freeware_bonus_fire)
        bonus_fire_bullets_timer = 8;
    else if (PICKUP_ID == freeware_bonus_weapon) {
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10002
        // 0x40772e draws the weapon when collected. A pistol picked up later has 15 rounds.
        int weapon = crt_rand() % 8 + 1;
        while (weapon == PLAYER.weapon)
            weapon = crt_rand() % 7 + 1;
        weapon_assign_player(current_player_index, weapon);
#else
        weapon_assign_player(current_player_index, PICKUP_WEAPON);
#endif
    }
    else if (PICKUP_ID == freeware_bonus_freeze)
        UI_FIELD(bonus_freeze_timer, run.freeze) = 5;
    else if (PICKUP_ID == freeware_bonus_nuke) {
        BOMB_POS = PICKUP_POS;
        BOMB_AGE = 0;
        UI_FIELD(freeware_camera_shake, camera_shake).x = 10;
        UI_FIELD(freeware_camera_shake, camera_shake).y = 10;
        sfx_play_panned(21, .45f, .5f);
    } else if (PICKUP_ID == freeware_bonus_shield)
        SHIELD = 6;
    else if (PICKUP_ID == freeware_bonus_time) {
        freeware_refill_clip();
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.actor(current_player_index).cooldown = PLAYER.cooldown;
#endif
        UI_FIELD(bonus_reflex_boost_timer, run.slow) = 4;
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
    if (UI_FIELD(PLAYER.health, actor(current_player_index).health) <= 0)
        return;
    if (PLAYER.perks[perk_id_radioactive] > 0) {
        source(5);
        destination(2);
        bind(texture("glow"));
        float alpha = (float)((sin(freeware_simulation_clock) + 1) * .1875f + .25f);
        tint(.3f, .6f, .3f, alpha);
        uv(0, 0, 1, 1);
        angle(0);
        begin();
        float size = (alpha + .75f) * 64;
        quad(CAMERA.x + POS.x - size * .5f, CAMERA.y + POS.y - size * .5f, size, size);
        end();
    }
    player_sheet();
    source(1);
    destination(6);
    const freeware_player_t &pose = PLAYER;
    int cell = (int)(pose.walk_phase + .5f);
    float dx = (float)(cos((double)pose.aim_heading + 1.57079637f) * pose.muzzle_flash * 12);
    float dy = (float)(sin((double)pose.aim_heading + 1.57079637f) * pose.muzzle_flash * 12);
    if (PLAYER.perks[perk_id_almost_invisible] > 0)
        tint(1, 1, 1, visibility() * .5f);
    else
        tint(1, 1, 1, .35f);
    angle(PLAYER.heading);
    atlas(cell);
    begin();
    upper_left(PLAYER.size * .5f - 2, 0, 0);
    quad(freeware_draw_point[0].x + 1, freeware_draw_point[0].y + 1, PLAYER.size * 1.02f, PLAYER.size * 1.02f);
    atlas(16 + cell);
    angle(PLAYER.aim_heading);
    upper_left(PLAYER.size * .5f, dx, dy);
    quad(freeware_draw_point[0].x + 1, freeware_draw_point[0].y + 1, PLAYER.size * 1.03f, PLAYER.size * 1.03f);
    end();
    player_sheet();
    source(5);
    destination(6);
    begin();
    if (PLAYER.perks[perk_id_almost_invisible] > 0)
        tint(1, 1, 1, visibility());
    else
        tint(1, 1, 1, 1);
    angle(PLAYER.heading);
    atlas(cell);
    upper_left(PLAYER.size * .5f, 0, 0);
    quad(freeware_draw_point[0].x, freeware_draw_point[0].y, PLAYER.size, PLAYER.size);
    float alpha = 1;
    if (PLAYER.perks[perk_id_almost_invisible] > 0)
        alpha = visibility();
    tint(1, 1, 1, alpha);
    if (config_player_count > 1) {
        if (current_player_index == 0)
            tint(.3f, .3f, 1, alpha);
        else
            tint(1, .55f, .35f, alpha);
    }
    atlas(16 + cell);
    angle(PLAYER.aim_heading);
    upper_left(PLAYER.size * .5f, dx, dy);
    quad(freeware_draw_point[0].x, freeware_draw_point[0].y, PLAYER.size, PLAYER.size);
    end();
    collect();
    if (SHIELD > 0) {
        source(5);
        destination(2);
        bind(texture("shockwave"));
        alpha = (float)((sin(freeware_simulation_clock) + 1) * .25 + SHIELD);
        if (SHIELD < 1)
            alpha *= SHIELD;
        if (alpha > 1)
            alpha = 1;
        tint(91.f / 255, 180.f / 255, 1, alpha * .4f);
        uv(0, 0, 1, 1);
        float r = (float)sin(freeware_simulation_clock * 3) + 17.5f;
        dx = (float)(cos((double)PLAYER.aim_heading - 1.57079637f) * 3);
        dy = (float)(sin((double)PLAYER.aim_heading - 1.57079637f) * 3);
        angle(freeware_simulation_clock * 2);
        begin();
        quad(CAMERA.x + POS.x - r + dx, dy + POS.y + CAMERA.y - r, r + r, r + r);
        tint(91.f / 255, 180.f / 255, 1, alpha * .1f);
        r = (float)(sin(freeware_simulation_clock * 3) + 18);
        angle(freeware_simulation_clock * -2);
        quad(CAMERA.x + POS.x - r + dx, dy + POS.y + CAMERA.y - r, r + r, r + r);
        end();
        destination(6);
    }
}
