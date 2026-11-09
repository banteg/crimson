// Draw one menu page and update keyboard hover. The 1.4.0 callback shares its lower corner between pages.
#ifdef CRIMSON_FREEWARE_CLIENT
const int count = which == main_page ? freeware::main_row_count : which == options_page ? freeware::option_row_count : 5;
#else
const int main_count = FREEWARE_EDITION == 10002 ? 6 : FREEWARE_EDITION == 10300 ? 7 : 8;
const int option_count = FREEWARE_EDITION == 10002 ? 9 : FREEWARE_EDITION == 10300 ? 11 : 12;
const int count = which == main_page ? main_count : which == options_page ? option_count : 5;
#endif
// 1.3.0 uses the same 26-pixel increment and hitbox at 0x415715 and 0x415751.
const float option_spacing = FREEWARE_EDITION == 10300 ? 26.f : 21.f;
float font_scale = FREEWARE_EDITION < 10400 || which == main_page ? .75435f : .65f;
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION != 10300
if (FREEWARE_EDITION != 10400 || which != main_page)
    grim_interface_ptr->grim_set_config_var(frame_font_scale, font_scale);
#endif
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION >= 10400
if (which == online_page) {
#ifdef CRIMSON_FREEWARE_CLIENT
    label(G.update_info.c_str(), 10, 10, font_scale, .2f, 1, .7f, .9f);
#else
    grim_interface_ptr->grim_set_color(.2f, 1, .7f, .9f);
    grim_interface_ptr->grim_draw_text_mono_fmt(10, 10, "%s", freeware_update_info);
#endif
}
#endif
int &hover = FIELD(freeware_perk_hover, perk_hover);
hover = -1;
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION < 10300
int index;
#endif
for (index = 0; index < count; ++index) {
#ifdef CRIMSON_FREEWARE_CLIENT
    std::string label = which == main_page      ? freeware::menu_row(G, index).label
                        : which == options_page ? G.option(freeware::option_action(index))
                                                : freeware::online_labels[index];
    const char *name = label.c_str();
    const float mx = G.cursor_x, my = G.cursor_y;
#else
#if FREEWARE_EDITION < 10400
    char *const &name = which == main_page ? freeware_main_labels[index] : freeware_option_labels[index];
#else
    char *const &name = which == main_page ? freeware_main_labels[index]
                        : which == options_page ? freeware_option_labels[index]
                                                : freeware_online_labels[index];
#endif
    const float mx = freeware_aim_screen.x, my = freeware_aim_screen.y;
#endif
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION != 10400
    vec2f_t position;
#endif
    position.x = (float)(screen_width / 2 - (which == main_page ? 100 : 140));
#ifdef CRIMSON_FREEWARE_CLIENT
    position.y = which == main_page ? freeware::main_row_top + index * 32.f : 170.f + index * option_spacing;
    if (FREEWARE_EDITION == 10002 && which == options_page)
        position.y = 180.f + index * 32.f;
    const int action = which == main_page ? freeware::main_action(index) : index;
#else
    position.y = which == main_page ? 200.f + index * 32.f : 170.f + index * option_spacing;
    if (FREEWARE_EDITION == 10002)
        position.y = (which == main_page ? 220.f : 180.f) + index * 32.f;
#if FREEWARE_EDITION == 10002
    const int action = native_menu_action(which, index);
#endif
#endif
#if FREEWARE_EDITION == 10002
    const float row_height = 30.f;
#else
    const float row_height = which == main_page ? 30.f : option_spacing;
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
    if ((unsigned char)freeware_point_in_rect(&freeware_aim_screen, &position,
            FramePoint(position.x + strlen(name) * 16.f, position.y + row_height).address()))
        hover = index;
    if (hover == index)
        grim_interface_ptr->grim_set_color(1, 1, 1, .9f);
    else if (SELECTED == index)
        grim_interface_ptr->grim_set_color(1, 1, 1, .7f);
    else
        grim_interface_ptr->grim_set_color(1, 1, 1, .6f);
    if (which == online_page && index == 2)
        grim_interface_ptr->grim_set_color(1, 1, 1, .2f);
    if (which == main_page && ACTIVE && index == 1)
        grim_interface_ptr->grim_set_color(.6f, .6f, .6f, .4f);
    if (which == main_page && ACTIVE && index == 2)
        grim_interface_ptr->grim_set_color(.6f, .6f, .6f, .4f);
    grim_interface_ptr->grim_draw_text_mono(position.x, position.y, name);
#else
    if (mx > position.x && my > position.y && mx < position.x + strlen(name) * 16.f && my < position.y + row_height)
        hover = index;
#if FREEWARE_EDITION == 10002
    float light = 1, alpha = hover == index ? .9f : .6f;
#else
    float light = 1, alpha = hover == index ? .9f : SELECTED == index ? .7f : .6f;
#endif
    if (which == online_page && index == 2)
        alpha = .2f;
    if (which == main_page && ACTIVE && (action == 1 || action == 2)) {
        light = .6f;
        alpha = .4f;
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    G.frame_labels.push_back({name, position.x, position.y, font_scale, {light, light, light, alpha}, G.frame_sprites.size()});
#else
    grim_interface_ptr->grim_set_color(light, light, light, alpha);
    grim_interface_ptr->grim_draw_text_mono(position.x, position.y, (char *)name);
#endif
#endif
}
#if FREEWARE_EDITION == 10300 || (!defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10400)
if ((FREEWARE_EDITION == 10300 || !FIELD(console_open_flag, console_open)) && menu_key(0xc8)) {
    --SELECTED;
    if (SELECTED > count - 1) SELECTED = count - 1;
    else if (SELECTED < 0) SELECTED = 0;
    hover = SELECTED;
}
if ((FREEWARE_EDITION == 10300 || !FIELD(console_open_flag, console_open)) && menu_key(0xd0)) {
    ++SELECTED;
    if (SELECTED > count - 1) SELECTED = count - 1;
    else if (SELECTED < 0) SELECTED = 0;
    hover = SELECTED;
}
#endif
