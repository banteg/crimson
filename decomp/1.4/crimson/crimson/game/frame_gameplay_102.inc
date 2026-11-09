// 1.0.2 state 3, immediately preceding the HUD (0x40cf97..0x40dab9).
__forceinline void gameplay_spawn102() {
    if (config_game_mode == 2)
        P(current_player_index).weapon = 2;
    SPAWN_TIMER -= frame_dt;
    if (SPAWN_TIMER < 0.f) {
        if (config_game_mode == 2) {
            SPAWN_TIMER = .01f;
            effect_color_t tint = {SECONDS * .0083333338f, 10.f / SECONDS,
                                   (float)sin(SECONDS * .1f), 1.f};
            clamp_spawn_color(tint.r);
            clamp_spawn_color(tint.g);
            clamp_spawn_color(tint.b);
            vec2f_t east = {(float)freeware_arena_width, freeware_arena_height * .5f};
            creature_spawn(&east, &tint, 1);
        } else if (freeware_spawn_enabled) {
            SPAWN_TIMER = 1.f - FIELD(P(current_player_index).experience, run.experience) * .00001f;
            if (SPAWN_TIMER < .2f)
                SPAWN_TIMER = .2f;
            spawn_edge();
        }
    }
}

extern "C" {
extern vec2f_t freeware_draw_point[2];
extern int world_arrow_marker_texture;
}

// The single-precision point arithmetic mirrors the expressions in the early
// rendering passes. In particular the unit vector is rounded before scaling.
__forceinline FramePoint102 aim_add102(const vec2f_t &a, const vec2f_t &b) {
    return FramePoint102(a.x + b.x, a.y + b.y);
}
__forceinline FramePoint102 aim_sub102(const vec2f_t &a, const vec2f_t &b) {
    return FramePoint102(a.x - b.x, a.y - b.y);
}
__forceinline FramePoint102 aim_mul102(const vec2f_t &a, const float &scale) {
    return FramePoint102(a.x * scale, a.y * scale);
}
__forceinline float aim_length102(vec2f_t d) { return sqrtf(d.x * d.x + d.y * d.y); }

#ifdef CRIMSON_FREEWARE_CLIENT
#define AIM_TINT_102 ui140::tint
#define AIM_ANGLE_102 ui140::angle
#define AIM_QUAD_102 ui140::quad
#else
#define AIM_TINT_102 grim_interface_ptr->grim_set_color
#define AIM_ANGLE_102 grim_interface_ptr->grim_set_rotation
#define AIM_QUAD_102 grim_interface_ptr->grim_draw_quad
#endif

__forceinline void aim_overlays_102() {
    using namespace ui140;
    if (bonus_fire_bullets_timer > 0) {
        menu_blend(true);
        bind("part");
        uv(0, 0, 1, 1);
        if (bonus_fire_bullets_timer < 1)
            AIM_TINT_102(1, 1, 1, bonus_fire_bullets_timer);
        else
            AIM_TINT_102(1, 1, 1, 1);
        begin();
        AIM_QUAD_102(MOUSE_X - 32, MOUSE_Y - 32, 64, 64);
        end();
    }
    menu_blend(false);
#ifdef CRIMSON_FREEWARE_CLIENT
    const FramePoint102 cursor(MOUSE_X, MOUSE_Y);
#else
    const vec2f_t &cursor = freeware_aim_screen;
#endif
    const float size = aim_length102(aim_sub102(aim_sub102(cursor, P(current_player_index).position), CAM))
                       * P(current_player_index).spread * .25f;
    if (size < 32)
        bind("aim32");
    else if (size < 64)
        bind("aim64");
    else
        bind("aim128");
    AIM_ANGLE_102(0);
    uv(0, 0, 1, 1);
    AIM_TINT_102(1, 1, 1, .64f);
    begin();
    freeware_draw_point[0] = aim_sub102(cursor, FramePoint102(size * .5f, size * .5f));
    AIM_QUAD_102(freeware_draw_point[0].x, freeware_draw_point[0].y, size, size);
    end();

    AIM_ANGLE_102(P(current_player_index).heading);
#ifdef CRIMSON_FREEWARE_CLIENT
    bind("arrow");
#else
    bind(world_arrow_marker_texture);
#endif
    AIM_TINT_102(1, 1, 1, .64f);
    begin();
    const float heading = P(current_player_index).heading - 1.57079637f;
    FramePoint102 dir(cosf(heading), sinf(heading));
    freeware_draw_point[0] = aim_sub102(
        aim_add102(aim_add102(CAM, P(current_player_index).position), aim_mul102(dir, 60.f)),
        FramePoint102(16.f, 16.f));
    AIM_QUAD_102(freeware_draw_point[0].x, freeware_draw_point[0].y, 32, 32);
    end();
}
#undef AIM_TINT_102
#undef AIM_ANGLE_102
#undef AIM_QUAD_102

__forceinline void combustion_particle102(const vec2f_t *pos, float intensity) {
    vec2f_t zero = {0, 0};
    fx_spawn_particle(pos, (crt_rand() % 628) * .01f, &zero, intensity);
}

__forceinline void target_perks102() {
    int owner_index = current_player_index;
    if (PLAYER_PERK(owner_index, perk_id_see_health) <= 0 &&
        PLAYER_PERK(owner_index, perk_id_spontaneously_combusteous) <= 0)
        return;

    vec2f_t aim = {FIELD(freeware_aim_screen.x, cursor_x) - CAM.x,
                   FIELD(freeware_aim_screen.y, cursor_y) - CAM.y};
    int id = creature_find_in_radius(&aim, 10.f);
    if (id == -1)
        return;

    if (PLAYER_PERK(current_player_index, perk_id_see_health) > 0) {
#ifdef CRIMSON_FREEWARE_CLIENT
        char output[40];
        sprintf(output, "health %d", (int)creature_pool[id].health);
        label(output, G.cursor_x, G.cursor_y + 32.f, .5f, 1, 1, 1, .64f);
#else
        grim_interface_ptr->grim_set_color(1, 1, 1, .64f);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .5f);
        sprintf(freeware_ui_buffer, "health %d", (int)creature_pool[id].health);
        grim_interface_ptr->grim_draw_text_mono(freeware_aim_screen.x, freeware_aim_screen.y + 32.f,
                                                freeware_ui_buffer);
#endif
    }
    if (PLAYER_PERK(current_player_index, perk_id_spontaneously_combusteous) > 0) {
        // In the 0x68-byte 1.0.2 creature, the plague and combustion ticks share +0x04.
        creature_pool[id].hit_flash_timer -= frame_dt;
        if (creature_pool[id].hit_flash_timer < 0) {
            creature_pool[id].hit_flash_timer = .5f;
            combustion_particle102(&creature_pool[id].position, .8f);
            combustion_particle102(&creature_pool[id].position, .6f);
            combustion_particle102(&creature_pool[id].position, .4f);
            combustion_particle102(&creature_pool[id].position, .3f);
            combustion_particle102(&creature_pool[id].position, .2f);
            fx_queue_add_random(&creature_pool[id].position);
        }
    }
}

__forceinline void timed_perks102() {
    if (JINX > 0)
        JINX -= frame_dt;
    if (JINX < 0 && PLAYER_PERK(current_player_index, perk_id_jinxed) > 0) {
        JINX = .6f;
        int slot = crt_rand() % 127;
        if (creature_pool[slot].active) {
            creature_pool[slot].health = -1;
            creature_pool[slot].death_timer -= frame_dt * 20;
            FIELD(P(current_player_index).experience, run.experience) += (int)creature_pool[slot].freeware.reward;
            sfx_play_panned(3, .45f, .5f);
        }
    }
    if (PLAYER_PERK(current_player_index, perk_id_berserk_attack) > 0) {
        BERSERK -= frame_dt;
        if (BERSERK < 0) {
            if (crt_rand() % 15 == 2) {
                BERSERK = 12;
                sfx_play_panned(19, .45f, .5f);
            } else {
                BERSERK = 2;
            }
        }
    }
}

__forceinline void gameplay_before_hud102() {
    if (PICKUP_TIME > 0.f)
        PICKUP_TIME -= frame_dt;
    else {
        PICKUP_TIME = 0.f;
#ifdef CRIMSON_FREEWARE_CLIENT
        G.run.pickup.kind = freeware::Bonus::None;
#else
        freeware_pickup_id = freeware_no_pickup;
#endif
    }
    if (bonus_fire_bullets_timer > 0.f)
        bonus_fire_bullets_timer -= frame_dt;
    else
        bonus_fire_bullets_timer = 0.f;
    if (FREEZE > 0.f)
        FREEZE -= frame_dt;
    else
        FREEZE = 0.f;
    aim_overlays_102();
    target_perks102();
    timed_perks102();
    gameplay_spawn102();
}
