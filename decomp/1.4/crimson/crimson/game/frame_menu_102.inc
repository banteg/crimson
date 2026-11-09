static __forceinline void menu102_title(float clock, float age) {
    if (age < 1)
        grim_interface_ptr->grim_set_color(1, 1, 1, age);
    else
        grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_set_config_var(0xc, true);
    vec2f_t center = FramePoint102(320.f, 90.f);
    center.x += (float)cos(clock) * 5.f;
    center.y += (float)sin(clock) * 5.f;
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("crimsonland"));
    menu_blend(false);
    if (age < 1) {
        if (!freeware_credits_open && !freeware_scores_open)
            freeware_logo_angle = (1.f - (float)sin(age * 1.57079637f)) * 1.57079637f;
        else
            freeware_logo_angle = (float)sin(age * 1.57079637f) * 1.57079637f;
    }
    if (freeware_logo_angle < 0)
        freeware_logo_angle = 0;
    else if (freeware_logo_angle > 1.57079637f)
        freeware_logo_angle = 1.57079637f;
    if (!ACTIVE) {
        center.x += freeware_logo_angle * 50;
        center.y -= freeware_logo_angle * 30;
        grim_interface_ptr->grim_set_rotation(freeware_logo_angle);
    } else
        grim_interface_ptr->grim_set_rotation(0);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    if (!freeware_logo_visible) {
        if (age < 1)
            grim_interface_ptr->grim_set_color(1, 1, 1, age);
        else
            freeware_logo_visible = 1;
    }
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(center.x - 256, center.y - 64, 512, 512 - freeware_logo_angle * 30);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0xf, 2u);
}

__forceinline void menu102_toggle_label(char **slot, const unsigned char &flag, const char *on, const char *off) {
    crt_free(*slot);
    if (flag)
        *slot = strdup_malloc(on);
    else
        *slot = strdup_malloc(off);
}

// The six dynamic rows duplicate their current label each time the options page is drawn.
__forceinline void menu102_option_labels() {
    crt_free(freeware_option_labels[0]);
    if (config_movement_schemes[0] == 2)
        freeware_option_labels[0] = strdup_malloc("Control method: static");
    else
        freeware_option_labels[0] = strdup_malloc("Control method: relative");
    menu102_toggle_label(&freeware_option_labels[2], freeware_shadows, "Shadows: on", "Shadows: off");
    menu102_toggle_label(&freeware_option_labels[3], freeware_filter_sharp, "Background filter: sharp",
                         "Background filter: smooth");
    menu102_toggle_label(&freeware_option_labels[4], freeware_show_fps, "Show FPS: on", "Show FPS: off");
    menu102_toggle_label(&freeware_option_labels[5], freeware_glow, "Flame Glow FX: on", "Flame Glow FX: off");
    menu102_toggle_label(&freeware_option_labels[6], freeware_shell_marks, "Shell marks: on", "Shell marks: off");
}

// A return to the main page allows the same click to be checked by the main menu.
__forceinline void menu102_option_input() {
    if (freeware_options_open &&
        (grim_interface_ptr->grim_was_key_pressed(0x1c) || grim_interface_ptr->grim_was_mouse_button_pressed(0))) {
        if (freeware_perk_hover == 0)
            config_movement_schemes[0] = 3 - config_movement_schemes[0];
        else if (freeware_perk_hover == 2)
            freeware_shadows = freeware_shadows ? 0 : 1;
        else if (freeware_perk_hover == 3)
            freeware_filter_sharp = freeware_filter_sharp ? 0 : 1;
        else if (freeware_perk_hover == 4)
            freeware_show_fps = freeware_show_fps ? 0 : 1;
        else if (freeware_perk_hover == 5)
            freeware_glow = freeware_glow ? 0 : 1;
        else if (freeware_perk_hover == 6)
            freeware_shell_marks = freeware_shell_marks ? 0 : 1;
        else if (freeware_perk_hover == 8) {
            freeware_options_open = 0;
            freeware_perk_hover = 0;
        }
    }
}

static __forceinline void menu102_draw_row(int i, bool main, const vec2f_t &row, const vec2f_t &upper) {
    if ((unsigned char)freeware_point_in_rect(&freeware_aim_screen, &row, &upper))
        freeware_perk_hover = i;
    if (freeware_perk_hover == i)
        grim_interface_ptr->grim_set_color(1, 1, 1, .9f);
    else
        grim_interface_ptr->grim_set_color(1, 1, 1, .6f);
    if (main && ACTIVE && i == 1)
        grim_interface_ptr->grim_set_color(.6f, .6f, .6f, .4f);
    grim_interface_ptr->grim_draw_text_mono(row.x, row.y, main ? freeware_main_labels[i] : freeware_option_labels[i]);
}

__forceinline void cursor_particles_102(float phase, float orbit, float &alpha) {
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 2u);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("part"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(MOUSE_X - 32.0f, MOUSE_Y - 32.0f, 64, 64);

    alpha = (float)cos(phase);
    alpha = ((float)pow(alpha, 2.0) + 1.0f) * .5f;
    for (int step = 0; step < 6; step += 2) {
        grim_interface_ptr->grim_set_color(1, 1, 1, alpha);
        float angle = orbit + step * 1.0471976f;
        grim_interface_ptr->grim_draw_quad(MOUSE_X - 32.0f + (float)cos(angle) * 16.0f,
                                           MOUSE_Y - 32.0f + (float)sin(angle) * 16.0f, 64, 64);
    }
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 6u);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("aim32"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, .64f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(MOUSE_X - 16.0f, MOUSE_Y - 16.0f, 32, 32);
    grim_interface_ptr->grim_end_batch();
}
// The 1.0.2 menu carries snapshots of the clock and menu age across its draw calls.
__forceinline void menu_footer_102(float phase, float orbit, float &alpha) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .65435f);
    grim_interface_ptr->grim_set_color(1, 1, 1, .4f);
    grim_interface_ptr->grim_draw_text_mono(10, 455, "v 1.0.2");
    grim_interface_ptr->grim_draw_text_mono(310, 455, "2002 (c) 10tons entertainment");

    cursor_particles_102(phase, orbit, alpha);
}
