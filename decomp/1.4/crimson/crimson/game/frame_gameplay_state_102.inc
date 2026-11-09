// 1.0.2 state 3, immediately preceding the HUD (0x40cf97..0x40dab9).
{
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
    const int owner = current_player_index;
    if (PLAYER_PERK(owner, perk_id_see_health) > 0 || PLAYER_PERK(owner, perk_id_spontaneously_combusteous) > 0) {
        int id = creature_find_in_radius(FramePoint102(MOUSE_X - CAM.x, MOUSE_Y - CAM.y).address(), 10.f);
        if (id != -1) {
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
                    combustion_particle102(creature_pool[id].position, .8f, FramePoint102(0.f, 0.f));
                    combustion_particle102(creature_pool[id].position, .6f, FramePoint102(0.f, 0.f));
                    combustion_particle102(creature_pool[id].position, .4f, FramePoint102(0.f, 0.f));
                    combustion_particle102(creature_pool[id].position, .3f, FramePoint102(0.f, 0.f));
                    combustion_particle102(creature_pool[id].position, .2f, FramePoint102(0.f, 0.f));
                    fx_queue_add_random(&creature_pool[id].position);
                }
            }
        }
    }
    timed_perks102();
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
            creature_spawn(FramePoint102((float)freeware_arena_width, freeware_arena_height * .5f).address(), &tint, 1);
        } else if (freeware_spawn_enabled) {
            SPAWN_TIMER = 1.f - FIELD(P(current_player_index).experience, run.experience) * .00001f;
            if (SPAWN_TIMER < .2f)
                SPAWN_TIMER = .2f;
#include "frame_spawn_edge.inc"
        }
    }
}
