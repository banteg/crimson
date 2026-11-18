// Later freeware gameplay runs inside the dispatcher. Each particle and spawn call
// takes the address of its own temporary point for the duration of that call.
if (bonus_fire_bullets_timer > 0 && config_player_count == 1) {
    menu_blend(true);
    ui140::bind("part");
    ui140::uv(0, 0, 1, 1);
    if (bonus_fire_bullets_timer < 1)
        world_tint(1, 1, 1, bonus_fire_bullets_timer);
    else
        world_tint(1, 1, 1, 1);
    ui140::begin();
    world_quad(MOUSE_X - 32, MOUSE_Y - 32, 64, 64);
    ui140::end();
}
menu_blend(false);
for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
    if (HP(current_player_index) <= 0)
        continue;
    const freeware_player_t &p = P(current_player_index);
    float dx = p.aim.x - p.position.x;
    float dy = p.aim.y - p.position.y;
    float size = (float)sqrt((double)(dx * dx) + dy * dy) * p.spread * .25f;
    if (size < 16) {
        size = 16;
        ui140::bind("aim32");
    } else if (size < 32)
        ui140::bind("aim32");
    else if (size < 64)
        ui140::bind("aim64");
    else
        ui140::bind("aim128");

    world_angle(0);
    ui140::uv(0, 0, 1, 1);
    aim_color(1);
    ui140::begin();
    freeware_draw_point[0] = CAM + P(current_player_index).aim - AimPoint(size * .5f, size * .5f);
    world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size, size);
    ui140::end();

    world_tint(1, 1, .1f, .7f);
    ui140::bind("aimen");
    const float rotation = CLOCK + CLOCK;
    world_angle(rotation);
    ui140::begin();
    freeware_draw_point[0] = CAM + P(current_player_index).aim - 10.f;
    world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, 20, 20);
    ui140::end();
}
for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
    if (HP(current_player_index) <= 0)
        continue;
    world_angle(P(current_player_index).heading);
    world_sheet(world_arrow_marker_texture, "arrow");
    aim_color(FREEWARE_EDITION == 10300 ? .64f : .6f);
    ui140::begin();
    float angle = P(current_player_index).heading - 1.57079637f;
    AimPoint direction((float)cos(angle), (float)sin(angle));
    AimPoint offset(direction.x * 60.f, direction.y * 60.f);
    freeware_draw_point[0] = CAM + P(current_player_index).position + offset - 16.f;
    if (FREEWARE_EDITION == 10300 || FIELD(freeware_direction_arrow, direction_arrow))
        world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, 32, 32);
    ui140::end();
    // Each targeting perk observes the creature under this player's aim.
    if (P(current_player_index).perks[perk_id_see_health] <= 0 &&
        P(current_player_index).perks[perk_id_spontaneously_combusteous] <= 0 &&
        P(current_player_index).perks[perk_id_evil_eyes] <= 0)
        continue;
    int id = creature_find_in_radius(&P(current_player_index).aim, 10);
    if (id == -1)
        continue;
    if (P(current_player_index).perks[perk_id_see_health] > 0) {
#ifdef CRIMSON_FREEWARE_CLIENT
        char buf[40];
        sprintf(buf, "health %d", (int)creature_pool[id].health);
        label(buf, G.cursor_x, G.cursor_y + 32, .5f, 1, 1, 1, .64f);
#else
        grim_interface_ptr->grim_set_color(1, 1, 1, .64f);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .5f);
        sprintf(freeware_ui_buffer, "health %d", (int)creature_pool[id].health);
        grim_interface_ptr->grim_draw_text_mono(freeware_aim_screen.x, freeware_aim_screen.y + 32, freeware_ui_buffer);
#endif
    }
    if (P(current_player_index).perks[perk_id_spontaneously_combusteous] > 0) {
        const float remaining = creature_pool[id].anim_phase - frame_dt;
        creature_pool[id].anim_phase = remaining;
        if (remaining < 0.f) {
            creature_pool[id].anim_phase = .5f;
            fx_spawn_particle(&creature_pool[id].position, (crt_rand() % 628) * .01f, FramePoint(0.f, 0.f).address(), .8f);
            fx_spawn_particle(&creature_pool[id].position, (crt_rand() % 628) * .01f, FramePoint(0.f, 0.f).address(), .6f);
            fx_spawn_particle(&creature_pool[id].position, (crt_rand() % 628) * .01f, FramePoint(0.f, 0.f).address(), .4f);
            fx_spawn_particle(&creature_pool[id].position, (crt_rand() % 628) * .01f, FramePoint(0.f, 0.f).address(), .3f);
            fx_spawn_particle(&creature_pool[id].position, (crt_rand() % 628) * .01f, FramePoint(0.f, 0.f).address(), .2f);
            fx_queue_add_random(&creature_pool[id].position);
        }
    }
    if (P(current_player_index).perks[perk_id_evil_eyes] > 0 && FREEZE <= 0) {
        vec2f_t &position = creature_pool[id].position;
        float &x = position.x;
        x -= creature_pool[id].velocity.x;
        float &y = position.y;
        y -= creature_pool[id].velocity.y;
    }
}
current_player_index = 0;

timed_perks();

if (config_game_mode == 2) {
    P(0).weapon = 2;
    P(0).ammo = 30;
    P(1).weapon = 2;
    P(1).ammo = 30;
}
SPAWN_TIMER -= frame_dt * config_player_count;
if (config_game_mode != 3) {
    while (SPAWN_TIMER < 0) {
        if (config_game_mode == 2) {
            SPAWN_TIMER += .25;
            effect_color_t tint = {SECONDS * .0083333338f + .3f, 10.f / SECONDS + .3f,
                                   (float)sin(SECONDS * .1f) + .3f, 1};
            clamp_spawn_color(tint.r);
            clamp_spawn_color(tint.g);
            clamp_spawn_color(tint.b);
            creature_spawn(FramePoint(freeware_arena_width + 64.f,
                                      (float)cos(SECONDS) * 256.f + freeware_arena_height * .5f).address(), &tint, 1);
            creature_spawn(FramePoint(-64.f, (float)sin(SECONDS) * 256.f + freeware_arena_height * .5f).address(), &tint, 1);
        } else if (freeware_spawn_enabled) {
            SPAWN_TIMER += 1.f - FIELD(P(current_player_index).experience, run.experience) * .000016666667f;
            if (SPAWN_TIMER < .01f)
                SPAWN_TIMER = .01f;
#include "frame_spawn_edge.inc"
        }
#ifdef CRIMSON_FREEWARE_CLIENT
        // A disabled spawner cannot advance a negative timer.
        else
            break;
#endif
    }
}
