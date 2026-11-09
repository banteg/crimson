// Title decorations and logo for the later freeware menus.
if (freeware_assembly_sequence == 8) {
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("asmlogo"));
    menu_blend(true);
    grim_interface_ptr->grim_set_rotation(0);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_begin_batch();

    position.x = screen_width / 2 + cosf(age - .2f) * 5.f;
    position.y = 140.f + cosf(age - .2f) * 5.f;
    float direction = aim_angle(position - freeware_aim_screen);
    float length = aim_length(position - freeware_aim_screen) * .02f;
    length *= 20.f;
    for (int i = 1; i < length; i += 3) {
        grim_interface_ptr->grim_set_color(.7f, .8f, 1, .09f - i * .09f / length);
        grim_interface_ptr->grim_draw_quad(position.x - 89.f + cosf(direction) * i,
                position.y + sinf(direction) * i / 3.f, 178, 29);
    }
    grim_interface_ptr->grim_set_color(1, 1, 1, .7f);
    grim_interface_ptr->grim_draw_quad(position.x - 89.f, position.y, 178, 29);
    grim_interface_ptr->grim_end_batch();
}
if (freeware_birthday) {
#if FREEWARE_EDITION == 10300
    position.x = screen_width / 2 + cosf(age - .2f) * 5.f - 100.f;
    position.y = cosf(age - .2f) * 5.f + 170.f;
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_draw_text_mono(position.x, position.y, "Happy birthday !");
#else
    grim_interface_ptr->grim_set_config_var(frame_font_scale, 1.f);
    char message[] = "Happy birthday !";
    char glyph[] = "Happy birthday !";
    int count = strlen(message);
    for (int i = 0; i < count; ++i) {
        int phase = (int)(age * 4) * (i + 1);
        grim_interface_ptr->grim_set_color(((phase * -24) & 255) / 256.f, ((phase * 87) & 255) / 256.f,
                                           ((phase * -58) & 255) / 256.f, 1);
        memset(glyph, ' ', count);
        glyph[i] = message[i];
        grim_interface_ptr->grim_draw_text_mono(0, 0, glyph);
    }
#endif
}
#if FREEWARE_EDITION >= 10400
if (freeware_christmas) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, 1.f);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_draw_text_mono(0, 0, "Merry Christmas!");
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("b_freeze"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_begin_batch();
    for (int x = 0; x < screen_width; x += 17) {
        float snow_x = (float)x;
        grim_interface_ptr->grim_set_rotation(snow_x + (float)sin(age * .4f));
        float &y = freeware_snow_y[x];
        y += ((x * 34 % 5) + 1) * 5 * frame_dt;
        while (y > 150)
            y -= 200;
        float snow_y = y;
        if (snow_y < 0)
            grim_interface_ptr->grim_set_color(1, 1, 1, 0);
        else if (snow_y < 50)
            grim_interface_ptr->grim_set_color(1, 1, 1, snow_y * .02f);
        else if (snow_y > 100)
            grim_interface_ptr->grim_set_color(1, 1, 1, 1 - (snow_y - 100) * .02f);
        else
            grim_interface_ptr->grim_set_color(1, 1, 1, 1);
        grim_interface_ptr->grim_draw_quad(snow_x, snow_y, 32, 32);
    }
    grim_interface_ptr->grim_end_batch();
}
if (freeware_memorial) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .6f);
    position.x = screen_width / 2 + cosf(age - .2f) * 5.f - 100.f;
    position.y = cosf(age - .2f) * 5.f + 170.f;
    for (float d = 0; d < 16; d += .5f) {
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .6f + (d / 16.f) * .05f);
        grim_interface_ptr->grim_set_color(.1f, .4f, .7f, (1.f - d / 16.f) * .2f);
        grim_interface_ptr->grim_draw_text_mono(position.x - cosf(age - .2f) * d,
                                                position.y + sinf(age - .2f) * d * 2.f, "The World Grieves..");
    }
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .6f);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_draw_text_mono(position.x, position.y, "The World Grieves..");
}
if (freeware_solstice) {
    position.x = screen_width / 2 + cosf(age - .2f) * 5.f - 100.f;
    position.y = cosf(age - .2f) * 5.f + 170.f;
    grim_interface_ptr->grim_set_color(1, 1, 1, .15f);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("tl_tolmec"));
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_set_rotation(age * .2f);
    grim_interface_ptr->grim_draw_quad(100, 100, 256, 256);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_color(1, .8f, .2f, 1);
    grim_interface_ptr->grim_draw_text_mono(position.x, position.y, "Have a Nice End of the World !");
}
#endif

if (age < 1.f)
    grim_interface_ptr->grim_set_color(1, 1, 1, age);
else
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
grim_interface_ptr->grim_set_config_var(0x12, true);
vec2f_t base = {(float)(screen_width / 2), 90.f};
position = base;
position.x += (float)cos(menu_clock) * 5.f;
position.y += (float)sin(menu_clock) * 5.f;
frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("crimsonland"));
menu_blend(false);
if (age < 1.f) {
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
    position.x += freeware_logo_angle * 50.f;
    position.y -= freeware_logo_angle * 30.f;
    grim_interface_ptr->grim_set_rotation(freeware_logo_angle);
} else {
    grim_interface_ptr->grim_set_rotation(0);
}
grim_interface_ptr->grim_set_color(1, 1, 1, 1);
if (!freeware_logo_visible) {
    if (age < 1.f)
        grim_interface_ptr->grim_set_color(1, 1, 1, age);
    else
        freeware_logo_visible = 1;
}
grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
grim_interface_ptr->grim_begin_batch();
grim_interface_ptr->grim_draw_quad(position.x - 256.f, position.y - 64.f, 512.f, 512.f - freeware_logo_angle * 30.f);
grim_interface_ptr->grim_end_batch();
grim_interface_ptr->grim_set_config_var(0x15, 2u);
grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
