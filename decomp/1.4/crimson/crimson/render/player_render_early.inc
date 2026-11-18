#include <math.h>
#include "crimsonland_types.h"
#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int perk_id_almost_invisible, perk_id_radioactive;
extern float bonus_fire_bullets_timer, bonus_freeze_timer, freeware_simulation_clock, frame_dt;
extern int current_player_index, freeware_player_texture;
extern freeware_player_t player_state_table[2];
extern RenderPoint freeware_camera, freeware_aim_screen;
extern RenderPoint freeware_draw_point[2], freeware_atlas_uv[64];
extern int freeware_pickup_id, freeware_no_pickup;
extern int freeware_bonus_weapon, freeware_bonus_nuke, freeware_bonus_fire, freeware_bonus_freeze;
extern float freeware_pickup_time;
extern RenderPoint freeware_pickup_position;
int sfx_play_panned(int, float, float);
extern creature_t creature_pool[128];
extern particle_t particle_pool[128];
int crt_rand();
int fx_spawn_particle(const vec2f_t *, float, const vec2f_t *, float);
void fx_queue_add_random(const vec2f_t *);
}

#define PLAYER player_state_table[current_player_index]
#define PLAYER_POS (*(const RenderPoint *)&PLAYER.position)

static __forceinline void collect_pickup() {
    if (freeware_pickup_id == freeware_no_pickup || !(freeware_pickup_time > 0.0f))
        return;
    RenderPoint delta = PLAYER_POS - freeware_pickup_position;
    if (!((float)sqrt(delta.y * delta.y + delta.x * delta.x) < 32.0f))
        return;

    if (freeware_pickup_id == freeware_bonus_fire) {
        bonus_fire_bullets_timer = 8.0f;
    } else if (freeware_pickup_id == freeware_bonus_weapon) {
        int previous = PLAYER.weapon;
        PLAYER.weapon = crt_rand() % 8 + 1;
        while (PLAYER.weapon == previous)
            PLAYER.weapon = crt_rand() % 7 + 1;
        if (PLAYER.weapon == 1)
            PLAYER.clip_size = 15.0f;
        if (PLAYER.weapon == 2)
            PLAYER.clip_size = 30.0f;
        if (PLAYER.weapon == 3)
            PLAYER.clip_size = 15.0f;
        if (PLAYER.weapon == 5)
            PLAYER.clip_size = 20.0f;
        if (PLAYER.weapon == 4)
            PLAYER.clip_size = 30.0f;
        if (PLAYER.weapon == 6)
            PLAYER.clip_size = 20.0f;
        if (PLAYER.weapon == 7)
            PLAYER.clip_size = 20.0f;
        if (PLAYER.weapon == 8)
            PLAYER.clip_size = 30.0f;
        PLAYER.ammo = PLAYER.clip_size;
    } else if (freeware_pickup_id == freeware_bonus_freeze) {
        bonus_freeze_timer = 5.0f;
    } else if (freeware_pickup_id == freeware_bonus_nuke) {
        // The first nuke applies damage immediately to every active creature.
        for (int i = 0; i < 128; ++i) {
            if (!creature_pool[i].active)
                continue;
            vec2f_t zero = {0, 0};
            int particle = fx_spawn_particle(&creature_pool[i].position, (crt_rand() % 628) * .01f,
                                             &zero, .4f);
            particle_pool[particle].in_flight = 0;
            creature_pool[i].health -= crt_rand() % 50 + 10;
            fx_queue_add_random(&creature_pool[i].position);
            if (creature_pool[i].health < 0.0f) {
                creature_pool[i].death_timer -= frame_dt;
                PLAYER.experience += creature_pool[i].freeware.reward;
            }
        }
    }
    freeware_pickup_id = freeware_no_pickup;
    freeware_pickup_time = 0.0f;
    sfx_play_panned(18, .45f, .5f);
}

static __forceinline void tint_body(float opacity) {
    if (PLAYER.perks[perk_id_almost_invisible] > 0)
        grim_interface_ptr->grim_set_color(
            1, 1, 1, ((float)sin(freeware_simulation_clock) * .35f + .5f) * opacity);
    else
        grim_interface_ptr->grim_set_color(1, 1, 1, opacity);
}
static __forceinline void set_atlas(RenderPoint *table, int cell) {
    RenderPoint origin = table[cell];
    freeware_draw_point[0] = origin;
    freeware_draw_point[1] = table[cell] + RenderPoint(.125f, .125f);
    grim_interface_ptr->grim_set_uv(freeware_draw_point[0].x, freeware_draw_point[0].y,
                                    freeware_draw_point[1].x, freeware_draw_point[1].y);
}
// Crimsonland 1.0.2 at 0x406f50 draws both body layers and collects nearby pickups.
extern "C" void player_render() {
    grim_interface_ptr->grim_bind_texture(freeware_player_texture);
    grim_interface_ptr->grim_set_config_var(13, (unsigned)1);
    grim_interface_ptr->grim_set_config_var(14, (unsigned)6);
    int cell = (int)(PLAYER.walk_phase + .5f);
    grim_interface_ptr->grim_begin_batch();
    tint_body(.5f);
    grim_interface_ptr->grim_set_rotation(PLAYER.heading);
    set_atlas(freeware_atlas_uv, cell);
    freeware_draw_point[0] = freeware_camera + PLAYER_POS -
                             RenderPoint(PLAYER.size * .5f - 2.0f, PLAYER.size * .5f - 2.0f);
    float size = PLAYER.size * 1.04f;
    grim_interface_ptr->grim_draw_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size,
                                       size);
    grim_interface_ptr->grim_end_batch();
    if (PLAYER.perks[perk_id_radioactive] > 0) {
        grim_interface_ptr->grim_set_config_var(13, (unsigned)5);
        grim_interface_ptr->grim_set_config_var(14, (unsigned)2);
        grim_interface_ptr->grim_bind_texture(grim_interface_ptr->grim_get_texture_handle("glow"));
        float alpha = ((float)sin(freeware_simulation_clock) + 1.0f) * .1875f + .25f;
        grim_interface_ptr->grim_set_color(.3f, .6f, .3f, alpha);
        grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
        grim_interface_ptr->grim_set_rotation(0);
        grim_interface_ptr->grim_begin_batch();
        float scale = alpha + .75f;
        grim_interface_ptr->grim_draw_quad(freeware_camera.x + PLAYER.position.x - scale * 32,
                                           freeware_camera.y + PLAYER.position.y - scale * 32,
                                           scale * 64, scale * 64);
        grim_interface_ptr->grim_end_batch();
    }
    grim_interface_ptr->grim_bind_texture(freeware_player_texture);
    grim_interface_ptr->grim_set_config_var(13, (unsigned)5);
    grim_interface_ptr->grim_set_config_var(14, (unsigned)6);
    grim_interface_ptr->grim_begin_batch();
    tint_body(1.0f);
    grim_interface_ptr->grim_set_rotation(PLAYER.heading);
    set_atlas(freeware_atlas_uv, cell);
    freeware_draw_point[0] =
        freeware_camera + PLAYER_POS - RenderPoint(PLAYER.size * .5f, PLAYER.size * .5f);
    size = PLAYER.size * 1.04f;
    grim_interface_ptr->grim_draw_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size,
                                       size);
    tint_body(1.0f);
    set_atlas(freeware_atlas_uv + 16, cell);
    // The early torso aims at the screen cursor, independently of the walking heading.
    RenderPoint direction = PLAYER_POS - freeware_aim_screen + freeware_camera;
    float heading = (float)atan2(direction.y, direction.x) - 1.57079637f;
    grim_interface_ptr->grim_set_rotation(heading);
    float recoil_heading = heading + 1.57079637f;
    RenderPoint offset;
    offset = RenderPoint(cosf(recoil_heading) * PLAYER.muzzle_flash * 12,
                         sinf(recoil_heading) * PLAYER.muzzle_flash * 12);
    float torso_size = PLAYER.size;
    freeware_draw_point[0] =
        freeware_camera + PLAYER_POS - RenderPoint(PLAYER.size * .5f, PLAYER.size * .5f) + offset;
    grim_interface_ptr->grim_draw_quad(freeware_draw_point[0].x, freeware_draw_point[0].y,
                                       torso_size, torso_size);
    grim_interface_ptr->grim_end_batch();
    collect_pickup();
}
