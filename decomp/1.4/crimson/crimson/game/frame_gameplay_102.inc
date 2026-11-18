// Draw and simulation helpers for the 1.0.2 gameplay frame.
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
__forceinline float aim_distance102(const vec2f_t &a, const vec2f_t &b) {
    float dx = a.x - b.x, dy = a.y - b.y;
    return sqrtf(dx * dx + dy * dy);
}

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
    const float size = aim_distance102(aim_sub102(cursor, P(current_player_index).position), CAM)
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

__forceinline void combustion_particle102(const vec2f_t &pos, float intensity, const vec2f_t &velocity) {
    fx_spawn_particle(&pos, (crt_rand() % 628) * .01f, &velocity, intensity);
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
