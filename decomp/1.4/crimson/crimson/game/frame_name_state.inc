// Native 1.3.0 and 1.4.0 name entry submits Grim configuration values from the frame's exception scope.
#if FREEWARE_EDITION == 10300
#define SCORE_NAME_INPUT freeware_last_score.name
#else
#define SCORE_NAME_INPUT freeware_name_buffer
#endif
{
    if (config_game_mode == 3) {
        leave_name_entry();
        PLAYER_PERK(current_player_index, perk_id_reflex_boosted) = 0;
        STATE_SINCE = CLOCK;
        break;
    }
    if (FREEWARE_EDITION >= 10400 && freeware_cheated) {
        leave_name_entry();
        freeware_cheated = 0;
        STATE_SINCE = CLOCK;
        PLAYER_PERK(current_player_index, perk_id_reflex_boosted) = 0;
        break;
    }
    if (ACTIVE) {
        if (FREEWARE_EDITION >= 10400)
            highscore_load_table();
        freeware_name_length = 0;
        if (FREEWARE_EDITION >= 10400) {
            int score = config_game_mode == 2 ? XP : (int)SECONDS;
            freeware_rank = freeware_score_rank(score) + 1;
        }
    }
    ACTIVE = 0;
    begin_overlay();
    if (CLOCK - STATE_SINCE < 1.f) {
        freeware_name_alpha = CLOCK - STATE_SINCE;
    } else {
        freeware_name_alpha = 1.f;
    }
    if (FREEWARE_EDITION >= 10400 && freeware_name_alpha < .8f) {
        creatures();
        shots();
    }
    grim_interface_ptr->grim_begin_batch();
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("reaper"));
    grim_interface_ptr->grim_set_color(1, 1, 1, freeware_name_alpha);
    grim_interface_ptr->grim_draw_quad(10, 10, 128, 128);
    grim_interface_ptr->grim_end_batch();
    char *buf = freeware_ui_buffer;
    if (config_game_mode == 2) {
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .975435f);
        grim_interface_ptr->grim_set_color(.75f, .35f, .22f, freeware_name_alpha * .9f);
        grim_interface_ptr->grim_draw_text_mono(100, 50, "The Reaper got you.");
        grim_interface_ptr->grim_draw_text_mono(100, 50, "The Reaper got you.");
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
        grim_interface_ptr->grim_set_color(.85f, .55f, .35f, freeware_name_alpha * .8f);
        sprintf(buf, "Seconds survived: %d", (int)SECONDS);
        grim_interface_ptr->grim_draw_text_mono(120, 90, buf);
#if FREEWARE_EDITION >= 10400
        format_name_rank(buf);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .51435f);
#endif
    } else {
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .975435f);
        grim_interface_ptr->grim_set_color(.45f, .55f, .85f, freeware_name_alpha * .9f);
        grim_interface_ptr->grim_draw_text_mono(100, 50, "The Reaper got you.");
        grim_interface_ptr->grim_draw_text_mono(100, 50, "The Reaper got you.");
        grim_interface_ptr->grim_set_color(.25f, .55f, .85f, freeware_name_alpha * .9f);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
        grim_interface_ptr->grim_set_color(.85f, .75f, .85f, freeware_name_alpha * .8f);
        sprintf(buf, "Gained experience: %d", P(current_player_index).experience);
        grim_interface_ptr->grim_draw_text_mono(150, 90, buf);
#if FREEWARE_EDITION >= 10400
        format_name_rank(buf);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .51435f);
#endif
    }
#if FREEWARE_EDITION >= 10400
    grim_interface_ptr->grim_set_color(1, 1, 1, freeware_name_alpha);
#endif
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
    grim_interface_ptr->grim_set_color(1, 1, 1, freeware_name_alpha);
    grim_interface_ptr->grim_draw_text_mono(10, 165, "Who were you:");
    grim_interface_ptr->grim_set_config_var(frame_font_scale, 1.f);
    grim_interface_ptr->grim_draw_text_mono(50, 190, SCORE_NAME_INPUT);

    float fps = average_fps();
    if (fps < 50)
        ++freeware_low_fps_frames;
    if (freeware_low_fps_frames > 1500)
        freeware_shadows = 0;
    else if (freeware_low_fps_frames > 1000)
        freeware_glow = 0;
    else if (freeware_low_fps_frames > 500)
        freeware_smoke = 0;
    pulse = CLOCK;
    orbit = CLOCK + CLOCK;
    if ((float)sin(pulse * 6.f) > 0.f)
        grim_interface_ptr->grim_set_color(1, 1, 1, freeware_name_alpha);
    else
        grim_interface_ptr->grim_set_color(1, 1, 1, freeware_name_alpha * .4f);
    grim_interface_ptr->grim_draw_text_mono(50.f + strlen(SCORE_NAME_INPUT) * 16, 190, "_");
    grim_interface_ptr->grim_set_color(1, 1, 1, freeware_name_alpha);
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
    if (fps < 15)
        grim_interface_ptr->grim_draw_text_mono(50, 222, "(your fps is too low for highscore table)");
    grim_interface_ptr->grim_set_color(.511f, .5f, .5f, freeware_name_alpha * .8f);

    int c = (signed char)freeware_read_name_key();
    if (c != (signed char)0xa7) {
        sfx_play_panned(17, .45f, .5f);
        if (c == '\t') {
            freeware_save_score();
            SCALE = 1;
            enter(1);
            freeware_scores_open = 1;
            PLAYER_PERK(current_player_index, perk_id_reflex_boosted) = 0;
            STATE_SINCE = CLOCK;
            highscore_load_table();
            STATE_SINCE = CLOCK - 1;
            freeware_transition_pending = 0;
        } else {
            if (c == '\b') {
                if (freeware_name_length > 0)
                    --freeware_name_length;
            } else {
                SCORE_NAME_INPUT[freeware_name_length++] = (char)c;
                if (freeware_name_length > 31)
                    freeware_name_length = 31;
            }
            SCORE_NAME_INPUT[freeware_name_length] = 0;
        }
    }
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .66f);
    sprintf(buf, "Gained level: %d\nHit accuracy: %d%%\nFrags: %d\n", P(current_player_index).level,
            (int)((float)highscore_record_hits / highscore_record_shots_fired * 100.f), freeware_kills);
    grim_interface_ptr->grim_draw_text_mono(60, 320, buf);
    int index;
#include "frame_cursor.inc"
    grim_interface_ptr->grim_set_config_var(frame_font_scale, 1.f);
}
#undef SCORE_NAME_INPUT
