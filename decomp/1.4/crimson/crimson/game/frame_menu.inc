// Inlined menu branches of game_frame_update (0x419663..0x41bd74).
enum menu_page { main_page, options_page, online_page, scores_page, credits_page };
#ifndef CRIMSON_FREEWARE_CLIENT
#include "../../http/freeware_http.h"

extern "C" {
extern int freeware_menu_selected, freeware_perk_hover, freeware_configuring, config_movement_schemes[2];
extern int freeware_tips_sequence, freeware_assembly_sequence, freeware_levels_sequence;
extern unsigned char freeware_show_secret_hints, freeware_options_open, freeware_online_open, freeware_scores_open,
    freeware_credits_open, freeware_menu_music_pending, freeware_music_disabled, freeware_filter_sharp,
    freeware_show_fps, freeware_glow, freeware_smoke, freeware_shadows, freeware_shell_marks,
    freeware_direction_arrow, freeware_rebinding, freeware_calibrating, freeware_pause_perks;
extern char *freeware_main_labels[], *freeware_option_labels[], *freeware_online_labels[5];
void highscore_load_table();
extern unsigned char freeware_open_site, freeware_music_started;
extern int freeware_level_number;
void freeware_music_start(int), freeware_music_stop(int);
#if FREEWARE_EDITION < 10400
void freeware_title_track_start(int), freeware_title_track_fade();
#if FREEWARE_EDITION == 10300
void freeware_game_track_start(int), freeware_game_track_fade();
#endif
#endif
extern void *freeware_update_info;
}
#endif
#define SELECTED FIELD(freeware_menu_selected, selected)
#define CONFIGURING FIELD(freeware_configuring, configuring)
#define MENU_MUSIC FIELD(freeware_menu_music_pending, menu_music_pending)
__forceinline int page() {
#ifdef CRIMSON_FREEWARE_CLIENT
    switch (G.screen) {
    case freeware::Screen::Options:
        return options_page;
    case freeware::Screen::Online:
        return online_page;
    case freeware::Screen::Credits:
        return credits_page;
    case freeware::Screen::Scores:
        return scores_page;
    default:
        return main_page;
    }
#else
    if (freeware_credits_open)
        return credits_page;
    if (freeware_scores_open)
        return scores_page;
    if (freeware_options_open)
        return options_page;
#if FREEWARE_EDITION >= 10400
    if (freeware_online_open)
        return online_page;
#endif
    return main_page;
#endif
}
__forceinline void show_page(int id) {
#ifdef CRIMSON_FREEWARE_CLIENT
    switch (id) {
    case main_page:
        G.screen = freeware::Screen::Menu;
        break;
    case options_page:
        G.screen = freeware::Screen::Options;
        break;
    case online_page:
        G.screen = freeware::Screen::Online;
        break;
    case credits_page:
        G.screen = freeware::Screen::Credits;
        break;
    case scores_page:
        G.screen = freeware::Screen::Scores;
        break;
    }
    G.notice = 0;
#else
    freeware_options_open = id == options_page;
#if FREEWARE_EDITION >= 10400
    freeware_online_open = id == online_page;
#endif
    freeware_credits_open = id == credits_page;
    freeware_scores_open = id == scores_page;
    if (id == scores_page)
        highscore_load_table();
#endif
}
__forceinline bool menu_key(int key) {
#ifdef CRIMSON_FREEWARE_CLIENT
    switch (key) {
    case 0xc8:
        return INPUT.previous;
    case 0xd0:
        return INPUT.next;
    case 0x1c:
        return INPUT.accept;
    case 0x1e:
        return INPUT.key == 4;
    case 0x1f:
        return INPUT.key == 22;
    case 0x12:
        return INPUT.key == 8;
    case 0x32:
        return INPUT.key == 16;
    case 0x30:
        return INPUT.key == 5;
    case 0x26:
        return INPUT.key == 15;
    case 0x15:
        return INPUT.key == 28;
    case 0x14:
        return INPUT.key == 23;
    case 0x17:
        return INPUT.key == 12;
    case 0x19:
        return INPUT.key == 19;
    default:
        return false;
    }
#else
    return grim_interface_ptr->grim_was_key_pressed(key);
#endif
}
__forceinline void menu_secrets() {
#if FREEWARE_EDITION != 10002
#ifdef CRIMSON_FREEWARE_CLIENT
    if (!INPUT.ctrl)
        return;
#else
    if (!grim_interface_ptr->grim_is_key_down(0x1d))
        return;
#endif
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
    // Ctrl+LEVELS, six independent key-edge tests at 0x4145b3..0x414671.
    const int levels[] = {15, 8, 25, 8, 15, 22}; // SDL scancodes L E V E L S
    if (G.levels_sequence < 6 && INPUT.key == levels[G.levels_sequence] && ++G.levels_sequence == 6)
        sfx_play_panned(17, .45f, .5f);
#endif
    int &assembly = FIELD(freeware_assembly_sequence, assembly_sequence);
    const int sequence[8] = {0x1e, 0x1f, 0x1f, 0x12, 0x32, 0x30, 0x26, 0x15};
    for (int i = 0; i < 8; ++i) {
        if (assembly == i && menu_key(sequence[i])) {
            ++assembly;
            if (i == 7)
                sfx_play_panned(17, .45f, .5f);
        }
    }
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
    // 0x4145a6 checks Ctrl a second time. Each queried edge advances the live counter.
    if (grim_interface_ptr->grim_is_key_down(0x1d)) {
        const int levels[] = {0x26, 0x12, 0x2f, 0x12, 0x26, 0x1f};
        for (int i = 0; i < 6; ++i) {
            if (freeware_levels_sequence == i && menu_key(levels[i])) {
                if (i == 5)
                    sfx_play_panned(17, .45f, .5f);
                ++freeware_levels_sequence;
            }
        }
    }
#endif
#if FREEWARE_EDITION >= 10400
    int &tips = FIELD(freeware_tips_sequence, tips_sequence);
    if (tips == 0 && menu_key(0x14))
        ++tips;
    if (tips == 1 && menu_key(0x17))
        ++tips;
    if (tips == 2 && menu_key(0x19))
        ++tips;
    if (tips == 3 && menu_key(0x1f)) {
        FIELD(freeware_show_secret_hints, secret_hints) = 1;
        sfx_play_panned(17, .45f, .5f);
    }
#endif
#endif
}
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" {
extern unsigned char freeware_music_unavailable;
void crt_free(void *);
char *strdup_malloc(const char *);
}
__forceinline void set_label(char **slot, const char *text) {
    crt_free(*slot);
    *slot = strdup_malloc(text);
}
__forceinline void refresh_labels(int which) {
    set_label(freeware_main_labels, ACTIVE ? "Resume game." : "Begin game.");
#if FREEWARE_EDITION == 10002
    if (which != options_page)
        return;
    set_label(freeware_option_labels, config_movement_schemes[0] == 2 ? "Control method: static" : "Control method: relative");
    set_label(freeware_option_labels + 2, freeware_shadows ? "Shadows: on" : "Shadows: off");
    set_label(freeware_option_labels + 3, freeware_filter_sharp ? "Background filter: sharp" : "Background filter: smooth");
    set_label(freeware_option_labels + 4, freeware_show_fps ? "Show FPS: on" : "Show FPS: off");
    set_label(freeware_option_labels + 5, freeware_glow ? "Flame Glow FX: on" : "Flame Glow FX: off");
    set_label(freeware_option_labels + 6, freeware_shell_marks ? "Shell marks: on" : "Shell marks: off");
#else
    set_label(freeware_main_labels + 1, config_player_count == 1 ? "Players: one" : "Players: two");
    set_label(freeware_main_labels + 2, config_game_mode == 1   ? "Game mode: career"
                                        : config_game_mode == 2 ? "Game mode: survival"
                                        : config_game_mode == 3 ? "Game mode: Level Test"
                                                                : "Game mode: Level Edit");
    set_label(freeware_main_labels + (FREEWARE_EDITION == 10300 ? 6 : 7), ACTIVE ? "End current game." : "End.");
    if (which != options_page)
        return;
    set_label(freeware_option_labels, CONFIGURING ? "Configure for: Player 2" : "Configure for: Player 1");
    int move = config_movement_schemes[CONFIGURING];
    set_label(freeware_option_labels + 1, move == 2   ? "Control method: kb static"
                                          : move == 1 ? "Control method: kb relative"
                                          : FREEWARE_EDITION == 10300 ? "Control method: joystic static" : "Control method: joystick static");
    int aim = config_aim_schemes[CONFIGURING];
#if FREEWARE_EDITION == 10300
    set_label(freeware_option_labels + 2, aim == 0 ? "Aiming device: mouse" : aim == 1 ? "Aiming device: keyboard" : "Aiming device: joystick 'hat'");
#else
    set_label(freeware_option_labels + 2, aim == 0   ? "Aiming device: mouse static"
                                          : aim == 1 ? "Aiming device: mouse relative"
                                          : aim == 2 ? "Aiming device: keyboard"
                                                     : "Aiming device: joystickk 'hat'");
#endif
#if FREEWARE_EDITION == 10300
    set_label(freeware_option_labels + 3, freeware_music_disabled ? "Music: off" : "Music: on");
#else
    set_label(freeware_option_labels + 3, freeware_music_disabled      ? "Music: off"
                                          : freeware_music_unavailable ? "Music: on (restart to enable playback)"
                                                                       : "Music: on");
#endif
    set_label(freeware_option_labels + 4,
              freeware_filter_sharp ? "Background filter: sharp" : "Background filter: smooth");
    set_label(freeware_option_labels + 5, freeware_show_fps ? "Show FPS: on" : "Show FPS: off");
    set_label(freeware_option_labels + 6,
              freeware_glow ? "Glow, Smoke & Shadow FX: on" : "Glow, Smoke & Shadow FX: off");
    set_label(freeware_option_labels + 7, freeware_shell_marks ? "Shell marks: on" : "Shell marks: off");
#if FREEWARE_EDITION >= 10400
    set_label(freeware_option_labels + 8,
              freeware_direction_arrow ? "Direction Arrow: on" : "Direction Arrow: off");
#endif
#endif
}
__forceinline int native_menu_action(int which, int row) {
#if FREEWARE_EDITION == 10002
    if (which == main_page)
        return row == 0 ? 0 : row == 5 ? 7 : row + 1;
    static const int options[] = {1, 12, 13, 4, 5, 6, 7, 14, 11};
    return options[row];
#elif FREEWARE_EDITION == 10300
    return (which == main_page && row == 6) || (which == options_page && row >= 8) ? row + 1 : row;
#else
    return row;
#endif
}
#endif
__forceinline int menu_rows(int which) {
#ifdef CRIMSON_FREEWARE_CLIENT
    const int count = which == main_page ? freeware::main_row_count : which == options_page ? freeware::option_row_count : 5;
#else
    const int main_count = FREEWARE_EDITION == 10002 ? 6 : FREEWARE_EDITION == 10300 ? 7 : 8;
    const int option_count = FREEWARE_EDITION == 10002 ? 9 : FREEWARE_EDITION == 10300 ? 11 : 12;
    const int count = which == main_page ? main_count : which == options_page ? option_count : 5;
#endif
    // 1.3.0 uses the same 26-pixel increment and hitbox at 0x415715 and 0x415751.
    const float option_spacing = FREEWARE_EDITION == 10300 ? 26.f : 21.f;
    float x = (float)(screen_width / 2 - (which == main_page ? 100 : 140));
    float font_scale = which == main_page ? .75435f : .65f;
#ifndef CRIMSON_FREEWARE_CLIENT
    if (FREEWARE_EDITION < 10400)
        font_scale = .75435f;
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
    for (int i = 0; i < count; ++i) {
#ifdef CRIMSON_FREEWARE_CLIENT
        std::string label = which == main_page      ? freeware::menu_row(G, i).label
                            : which == options_page ? G.option(freeware::option_action(i))
                                                    : freeware::online_labels[i];
        const char *name = label.c_str();
        const float mx = G.cursor_x, my = G.cursor_y;
#else
#if FREEWARE_EDITION < 10400
        const char *name = which == main_page ? freeware_main_labels[i] : freeware_option_labels[i];
#else
        const char *name = which == main_page      ? freeware_main_labels[i]
                           : which == options_page ? freeware_option_labels[i]
                                                   : freeware_online_labels[i];
#endif
        const float mx = freeware_aim_screen.x, my = freeware_aim_screen.y;
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
        float y = which == main_page ? freeware::main_row_top + i * 32.f : 170.f + i * option_spacing;
        if (FREEWARE_EDITION == 10002 && which == options_page)
            y = 180.f + i * 32.f;
        const int action = which == main_page ? freeware::main_action(i) : i;
#else
        float y = which == main_page ? 200.f + i * 32.f : 170.f + i * option_spacing;
        if (FREEWARE_EDITION == 10002)
            y = (which == main_page ? 220.f : 180.f) + i * 32.f;
        const int action = native_menu_action(which, i);
#endif
#if FREEWARE_EDITION == 10002
        const float row_height = 30.f;
#else
        const float row_height = which == main_page ? 30.f : option_spacing;
#endif
        if (mx > x && my > y && mx < x + strlen(name) * 16.f && my < y + row_height)
            hover = i;
#if FREEWARE_EDITION == 10002
        float light = 1, alpha = hover == i ? .9f : .6f;
#else
        float light = 1, alpha = hover == i ? .9f : SELECTED == i ? .7f : .6f;
#endif
        if (which == online_page && i == 2)
            alpha = .2f;
        if (which == main_page && ACTIVE && (action == 1 || action == 2)) {
            light = .6f;
            alpha = .4f;
        }
#ifdef CRIMSON_FREEWARE_CLIENT
        G.frame_labels.push_back({name, x, y, font_scale, {light, light, light, alpha}, G.frame_sprites.size()});
#else
        grim_interface_ptr->grim_set_color(light, light, light, alpha);
        grim_interface_ptr->grim_draw_text_mono(x, y, (char *)name);
#endif
    }
#if FREEWARE_EDITION == 10002
    if (which == options_page && menu_key(0x1c))
        return hover;
#else
    if (menu_key(0xc8)) {
        --SELECTED;
        if (SELECTED < 0)
            SELECTED = 0;
        hover = SELECTED;
    }
    if (menu_key(0xd0)) {
        ++SELECTED;
        if (SELECTED >= count)
            SELECTED = count - 1;
        hover = SELECTED;
    }
    if (menu_key(0x1c)) {
        hover = SELECTED;
        return hover;
    }
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
    return INPUT.click ? hover : -1;
#else
    return grim_interface_ptr->grim_was_mouse_button_pressed(0) ? hover : -1;
#endif
}
__forceinline void menu_options(int row) {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10002
    // 0x40cd74. Sound volume and the spacer have no case in this switch.
    switch (row) {
    case 1: config_movement_schemes[0] = 3 - config_movement_schemes[0]; break;
    case 13: freeware_shadows = !freeware_shadows; break;
    case 4: freeware_filter_sharp = !freeware_filter_sharp; break;
    case 5: freeware_show_fps = !freeware_show_fps; break;
    case 6: freeware_glow = !freeware_glow; break;
    case 7: freeware_shell_marks = !freeware_shell_marks; break;
    case 11: freeware_options_open = 0; freeware_perk_hover = 0; break;
    }
#else
    switch (row) {
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10002
    case 12: // The sound-volume row and spacer have no action at 0x40cd74.
    case 14: return;
    case 13: G.shadows = !G.shadows; break;
#endif
    case 0:
        CONFIGURING = 1 - CONFIGURING;
        break;
    case 1:
#ifdef CRIMSON_FREEWARE_CLIENT
    {
#if FREEWARE_EDITION == 10002
        G.movement[0] = 1 - G.movement[0];
#else
        static const int next[] = {2, 0, 1};
        G.movement[CONFIGURING] = next[G.movement[CONFIGURING]];
#endif
    }
#else
        if (++config_movement_schemes[CONFIGURING] > 3)
            config_movement_schemes[CONFIGURING] = 1;
#endif
    break;
    case 2: {
        int &aim = FIELD(config_aim_schemes[CONFIGURING], aiming[CONFIGURING]);
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
        if (aim == 0) ++aim; // Slot 1 in the client settings is the later relative-mouse option.
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
        if (++aim > 2)
#else
        if (++aim > 3)
#endif
            aim = 0;
    } break;
    case 3:
#ifdef CRIMSON_FREEWARE_CLIENT
        G.music_enabled = !G.music_enabled;
#else
        freeware_music_disabled = !freeware_music_disabled;
#if FREEWARE_EDITION == 10300
        if (freeware_music_disabled) {
            freeware_title_track_fade();
            freeware_game_track_fade();
        } else if (ACTIVE)
            freeware_game_track_start(31);
        else
            freeware_title_track_start(30);
#endif
#endif
        break;
    case 4:
        FIELD(freeware_filter_sharp, smooth) = !FIELD(freeware_filter_sharp, smooth);
        break;
    case 5:
        FIELD(freeware_show_fps, show_fps) = !FIELD(freeware_show_fps, show_fps);
        break;
    case 6:
        FIELD(freeware_glow, effects) = !FIELD(freeware_glow, effects);
#ifndef CRIMSON_FREEWARE_CLIENT
        freeware_smoke = !freeware_smoke;
        freeware_shadows = !freeware_shadows;
#elif FREEWARE_EDITION != 10002
        G.smoke = !G.smoke;
        G.shadows = !G.shadows;
#endif
        break;
    case 7:
        FIELD(freeware_shell_marks, shell_marks) = !FIELD(freeware_shell_marks, shell_marks);
        break;
    case 8:
        FIELD(freeware_direction_arrow, direction_arrow) = !FIELD(freeware_direction_arrow, direction_arrow);
        break;
    case 9:
#ifdef CRIMSON_FREEWARE_CLIENT
        G.rebind = 0;
#else
        freeware_rebinding = 1;
#endif
        break;
    case 10:
#ifdef CRIMSON_FREEWARE_CLIENT
        G.calibration = 0;
#else
        freeware_calibrating = 1;
#endif
        break;
    case 11:
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
        freeware_options_open = 0;
        freeware_perk_hover = 0;
#else
        show_page(main_page);
        SELECTED = 0;
#endif
        break;
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    G.save_options();
#endif
#endif
}
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" {
extern float freeware_logo_angle, freeware_snow_y[];
extern unsigned char freeware_logo_visible, freeware_birthday, freeware_memorial, freeware_solstice,
    freeware_christmas;
}
#endif
__forceinline void menu_blend(bool additive) {
#ifdef CRIMSON_FREEWARE_CLIENT
    G.ui.destination_blend = additive ? 2 : 6;
#else
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, additive ? 2u : 6u);
#endif
}
__forceinline void menu_title(int which) {
    float age = CLOCK - STATE_SINCE;
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION >= 10300
    if (FIELD(freeware_assembly_sequence, assembly_sequence) == 8) {
        menu_blend(true);
        double wave = cos((double)age - .2f) * 5;
        float x = (float)(screen_width / 2 + wave), y = (float)(140 + wave);
        double dx = (double)x - MOUSE_X, dy = (double)y - MOUSE_Y;
        float length = (float)(sqrt(dx * dx + dy * dy) * .02f * 20);
        double angle = atan2(dy, dx);
        for (int i = 1; i < length; i += 3)
            sprite("asmlogo", x - 89 + (float)cos(angle) * i, y + (float)sin(angle) * i / 3.f, 178, 29, 0, .7f,
                   .8f, 1, .09f - i * .09f / length);
        sprite("asmlogo", x - 89, y, 178, 29, 0, 1, 1, 1, .7f);
    }
    if (FIELD(freeware_birthday, birthday)) {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
        float wave = (float)(cos((double)age - .2f) * 5);
        grim_interface_ptr->grim_set_color(1, 1, 1, 1);
        grim_interface_ptr->grim_draw_text_mono(screen_width / 2 + wave - 100, wave + 170, "Happy birthday !");
#else
        const char message[] = "Happy birthday !";
        int phase = (int)(age * 4);
        for (int i = 0; message[i]; ++i) {
            char glyph[sizeof(message)];
            memset(glyph, ' ', sizeof(message) - 1);
            glyph[sizeof(message) - 1] = 0;
            glyph[i] = message[i];
            int n = phase * (i + 1);
            label(glyph, 0, 0, 1, ((n * -24) & 255) / 256.f, ((n * 87) & 255) / 256.f, ((n * -58) & 255) / 256.f,
                  1);
        }
#endif
    }
#endif
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION >= 10400
    if (FIELD(freeware_christmas, christmas)) {
        label("Merry Christmas!", 0, 0, 1, 1, 1, 1, 1);
        for (int x = 0; x < screen_width; x += 17) {
            float &y = FIELD(freeware_snow_y, snow_y)[x];
            y += ((x * 34 % 5) + 1) * 5 * frame_dt;
            while (y > 150)
                y -= 200;
            float alpha = y < 0 ? 0 : y < 50 ? y * .02f : y > 100 ? 1 - (y - 100) * .02f : 1;
            sprite("b_freeze", (float)x, y, 32, 32, x + (float)sin(age * .4f), 1, 1, 1, alpha);
        }
    }
    if (FIELD(freeware_memorial, memorial)) {
        float cs = (float)cos((double)age - .2f), sn = (float)sin((double)age - .2f);
        float x = screen_width / 2 + cs * 5 - 100, y = cs * 5 + 170;
        for (float d = 0; d < 16; d += .5f) {
            float fade = d * .0625f;
            label("The World Grieves..", x - cs * d, y + sn * d * 2, .6f + fade * .05f, .1f, .4f, .7f,
                  (1 - fade) * .2f);
        }
        label("The World Grieves..", x, y, .6f, 1, 1, 1, 1);
    }
    if (FIELD(freeware_solstice, solstice)) {
        float wave = (float)cos((double)age - .2f) * 5;
        sprite("tl_tolmec", 100, 100, 256, 256, age * .2f, 1, 1, 1, .15f);
#ifdef CRIMSON_FREEWARE_CLIENT
        label("Have a Nice End of the World !", screen_width / 2 + wave - 100, wave + 170, G.ui.scale, 1, .8f, .2f,
              1);
#else
        grim_interface_ptr->grim_set_color(1, .8f, .2f, 1);
        grim_interface_ptr->grim_draw_text_mono(screen_width / 2 + wave - 100, wave + 170,
                                                "Have a Nice End of the World !");
#endif
    }
#endif
    float &angle = FIELD(freeware_logo_angle, logo_angle);
    if (age < 1) {
        double wave = sin((double)age * 1.57079637f);
        angle = (float)((which == scores_page || which == credits_page ? wave : 1 - wave) * 1.57079637f);
    }
    if (angle < 0)
        angle = 0;
    if (angle > 1.57079637f)
        angle = 1.57079637f;
    float x = (float)(screen_width / 2 + cos(CLOCK) * 5) - 256, y = (float)(90 + sin(CLOCK) * 5) - 64;
    if (!ACTIVE) {
        x += angle * 50;
        y -= angle * 30;
    }
    float alpha = 1;
    if (!FIELD(freeware_logo_visible, logo_visible)) {
        if (age >= 1)
            FIELD(freeware_logo_visible, logo_visible) = 1;
        else
            alpha = age;
    }
    menu_blend(false);
    sprite("crimsonland", x, y, 512, 512 - angle * 30, ACTIVE ? 0 : angle, 1, 1, 1, alpha);
}

#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" {
extern int freeware_setup_step, freeware_pad_threshold, freeware_pad_center_x, freeware_pad_center_y,
    freeware_pov_left, freeware_pov_right;
extern unsigned char freeware_saved_keys[10];
bool freeware_save_config(), config_load_presets();
bool input_move_up_active(), input_move_down_active(), input_move_left_active(), input_move_right_active();
}
#endif
extern "C" char *wrap_text_to_width_alloc(char *, int);
__forceinline bool setup_controls() {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10002
    return false;
#else
#ifdef CRIMSON_FREEWARE_CLIENT
    bool binding = G.rebind >= 0;
    if (!binding && G.calibration < 0)
        return false;
    int &step = binding ? G.rebind : G.calibration;
    int end = -1;
#else
    bool binding = freeware_rebinding != 0;
    if (!binding && !freeware_calibrating)
        return false;
    int &step = freeware_setup_step;
    int end = 0;
#endif
    if (binding) {
        const char *actions[] = {"UP", "DOWN", "LEFT", "RIGHT", "FIRE"};
        char prompt[48];
        sprintf(prompt, "Player %d %s", 1 + step / 5, actions[step % 5]);
        label("Press down key for..", 50, 200, .85435f, 1, 1, 1, .6f);
        label(prompt, 120, 250, .75435f, 1, 1, 1, .6f);
#ifdef CRIMSON_FREEWARE_CLIENT
        if (INPUT.key > 0) {
            G.keys[step / 5][step % 5] = INPUT.key;
            ++step;
        }
#else
        for (int key = 0; key < 256; ++key)
            if (grim_interface_ptr->grim_was_key_pressed(key)) {
                freeware_saved_keys[step++] = (unsigned char)key;
                break;
            }
#endif
        if (step < 10)
            return true;
    } else {
#ifdef CRIMSON_FREEWARE_CLIENT
        int x = (int)(1000 * INPUT.stick_x[CONFIGURING]), y = (int)(1000 * INPUT.stick_y[CONFIGURING]);
        int threshold = (int)(G.pad_threshold[CONFIGURING] * 1000 + .5f);
        float ax = INPUT.aim_x[CONFIGURING], ay = INPUT.aim_y[CONFIGURING];
        int pov = ax == 0 && ay == 0 ? -1 : (int)(atan2(ax, -ay) * 5729.5779513 + 36000.5) % 36000;
#else
        int x = grim_interface_ptr->grim_get_joystick_x(), y = grim_interface_ptr->grim_get_joystick_y();
        int &threshold = freeware_pad_threshold;
        int pov = grim_interface_ptr->grim_get_joystick_pov(0);
#endif
        const char *prompts[] = {
            "Center the joystick and press enter or a joystick button",
            "Set the joystick X/Y-Axis threshold with arrow keys up/down, press enter when done.",
            "If your joystick has 'hat' press it LEFT now and press enter. (press enter to skip this)",
            "If your joystick has 'hat' press it RIGHT now and press enter. (press enter to skip this)"};
        char status[128];
        if (step > 3) {
            step = end;
#ifndef CRIMSON_FREEWARE_CLIENT
            freeware_calibrating = 0;
            freeware_save_config();
            config_load_presets();
#else
            G.save_options();
#endif
            return true;
        }
        char *prompt = wrap_text_to_width_alloc((char *)prompts[step], 45);
        label(prompt, 50, 120, .70435f, 1, 1, 1, .6f);
#ifdef CRIMSON_FREEWARE_CLIENT
        delete[] prompt;
#else
        crt_free(prompt);
#endif
        int display_step = step;
        if (step == 0) {
            sprintf(status, "X-Axis: %d\nY-Axis: %d", x, y);
#ifdef CRIMSON_FREEWARE_CLIENT
            bool trigger = INPUT.pad_any[CONFIGURING];
#else
            bool trigger = false;
            for (int j = 0; j < 5; ++j)
                if (grim_interface_ptr->grim_is_joystick_button_down(j))
                    trigger = true;
#endif
            if (menu_key(0x1c) || trigger) {
#ifdef CRIMSON_FREEWARE_CLIENT
                G.pad_center[CONFIGURING].x = x * .001f;
                G.pad_center[CONFIGURING].y = y * .001f;
#else
                freeware_pad_center_x = x;
                freeware_pad_center_y = y;
#endif
                ++step;
            }
        } else if (step == 1) {
            if (menu_key(0xc8))
                threshold += 10;
            if (menu_key(0xd0))
                threshold -= 10;
            if (threshold < 0)
                threshold = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
            G.pad_threshold[CONFIGURING] = threshold * .001f;
#endif
            sprintf(status, "X/Y-Axis threshold: %d", threshold);
            if (menu_key(0x1c))
                ++step;
        } else {
            sprintf(status, "POV0 ('hat') status: %d", pov);
            if (menu_key(0x1c)) {
#ifdef CRIMSON_FREEWARE_CLIENT
                if (step == 2)
                    G.pad_left_pov[CONFIGURING] = pov;
                else
                    G.pad_right_pov[CONFIGURING] = pov;
#else
                if (step == 2)
                    freeware_pov_left = pov;
                else
                    freeware_pov_right = pov;
#endif
                ++step;
            }
        }
        label(status, 40, 250, .70435f, 1, 1, 1, .6f);
        if (display_step == 1) {
#ifdef CRIMSON_FREEWARE_CLIENT
            int dx = x - (int)(G.pad_center[CONFIGURING].x * 1000),
                dy = y - (int)(G.pad_center[CONFIGURING].y * 1000);
            sprintf(status, "Status:\n\nUp: %d\nDown: %d\nLeft: %d\nRight: %d", dy<-threshold, dy> threshold,
                    dx<-threshold, dx> threshold);
#else
            sprintf(status, "Status:\n\nUp: %d\nDown: %d\nLeft: %d\nRight: %d", input_move_up_active(),
                    input_move_down_active(), input_move_left_active(), input_move_right_active());
#endif
            label(status, 40, 300, .70435f, 1, 1, 1, .6f);
        }
        return true;
    }
    step = end;
#ifdef CRIMSON_FREEWARE_CLIENT
    G.save_options();
#else
    freeware_rebinding = 0;
    freeware_save_config();
    config_load_presets();
#endif
    return true;
#endif
}
__forceinline void cursor_particles(float pulse, float orbit) {
    float x = MOUSE_X - 32, y = MOUSE_Y - 32;
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 2u);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("part"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(x, y, 64, 64);
#else
    G.ui.destination_blend = 2;
    const float rotation = G.frame_sprites.empty() ? 0 : G.frame_sprites.back().angle;
    sprite("part", x, y, 64, 64, rotation, 1, 1, 1, 1);
#endif
    float alpha = (float)((pow(cos(pulse), 2) + 1) * .5);
    for (int step = 0; step < 6; step += 2) {
        double angle = orbit + (double)step * 1.0471976f;
        float px = (float)(x + cos(angle) * 16), py = (float)(y + sin(angle) * 16);
#ifdef CRIMSON_FREEWARE_CLIENT
        sprite("part", px, py, 64, 64, rotation, 1, 1, 1, alpha);
#else
        grim_interface_ptr->grim_set_color(1, 1, 1, alpha);
        grim_interface_ptr->grim_draw_quad(px, py, 64, 64);
#endif
    }
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 6u);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("aim32"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, .64f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(MOUSE_X - 16, MOUSE_Y - 16, 32, 32);
    grim_interface_ptr->grim_end_batch();
#else
    G.ui.destination_blend = 6;
    sprite("aim32", MOUSE_X - 16, MOUSE_Y - 16, 32, 32, rotation, 1, 1, 1, .64f);
#endif
}
__forceinline void menu_footer() {
#ifdef CRIMSON_FREEWARE_CLIENT
    const char *version = FREEWARE_EDITION == 10002 ? "v " FREEWARE_VERSION : "v" FREEWARE_VERSION;
#else
    const char *version = FREEWARE_EDITION == 10002 ? "v 1.0.2" : FREEWARE_EDITION == 10300 ? "v1.3.0" : "v1.4.0";
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION < 10400
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .65435f);
    grim_interface_ptr->grim_set_color(1, 1, 1, .4f);
    grim_interface_ptr->grim_draw_text_mono(10, (float)screen_height - 25, (char *)version);
    grim_interface_ptr->grim_draw_text_mono((float)screen_width - 330, (float)screen_height - 25,
                                            "2002 (c) 10tons entertainment");
#else
    label(version, 10, (float)screen_height - 25, .65435f, 1, 1, 1, .4f);
    label("2002 (c) 10tons entertainment", (float)screen_width - 330, (float)screen_height - 25, .65435f, 1, 1, 1,
          .4f);
#endif
    cursor_particles(CLOCK - STATE_SINCE, CLOCK);
}
__forceinline void menu_tracks(bool play_title) {
#ifndef CRIMSON_FREEWARE_CLIENT
#if FREEWARE_EDITION == 10002
    if (play_title)
        freeware_title_track_start(30);
    else
        freeware_title_track_fade();
#elif FREEWARE_EDITION == 10300
    if (!play_title)
        freeware_title_track_fade();
    freeware_game_track_fade();
    if (play_title)
        freeware_title_track_start(30);
#else
    freeware_music_stop(30);
    freeware_music_stop(29);
    freeware_music_stop(31);
    if (play_title)
        freeware_music_start(30);
#endif
#endif
}
__forceinline bool main_menu() {
    menu_secrets();
    int which = page();
    if (which != scores_page && MENU_MUSIC && !ACTIVE) {
        menu_tracks(true);
        MENU_MUSIC = 0;
        STATE_SINCE = CLOCK;
        FIELD(freeware_logo_angle, logo_angle) = 0;
    }
#ifndef CRIMSON_FREEWARE_CLIENT
    refresh_labels(which);
#endif
    menu_title(which);
    bool overlay = which == scores_page || which == credits_page;
#ifdef CRIMSON_FREEWARE_CLIENT
    if (!overlay && INPUT.escape && which != main_page) {
        show_page(main_page);
        SELECTED = 0;
        return true;
    }
#endif
    int row = -1;
    if (overlay || !setup_controls())
        row = menu_rows(overlay ? main_page : which);
    menu_footer();
    if (overlay) {
        if (which == scores_page)
            game_highscores_update();
        else
            game_credits_update();
        return true;
    }
    if (row < 0)
        return true;
#ifdef CRIMSON_FREEWARE_CLIENT
    if (which == main_page)
        row = freeware::main_action(row);
    else if (which == options_page)
        row = freeware::option_action(row);
#else
    row = native_menu_action(which, row);
#endif
    if (which == options_page) {
        menu_options(row);
        return true;
    }
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION >= 10400
    if (which == online_page) {
        if (row == 4) {
            show_page(main_page);
            SELECTED = 0;
        }
#ifdef CRIMSON_FREEWARE_CLIENT
        else if (row == 0)
            G.visit_website = true;
        else if (row == 1)
            G.update_info = "Installed version: 1.4.0. The 2002 update service is unavailable.";
#else
        else if (row == 0) {
            freeware_open_site = 1;
            quit_requested = 1;
        } else if (row == 1) {
            freeware_http_response *response = freeware_http_get("www.mbnet.fi", "~temper/crimsonland", "versioninfo.txt");
            if (response) {
                crt_free(freeware_update_info);
                freeware_update_info = response->data;
            }
        }
#endif
        return true;
    }
#endif
    switch (row) {
    case 0:
        if (!ACTIVE) {
            FIELD(freeware_logo_visible, logo_visible) = 0;
            MENU_MUSIC = 1;
            enter(3);
            FIELD(freeware_music_started, wind_started) = 1;
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION != 10002
            menu_tracks(false);
            freeware_current_map->clear();
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
            G.start();
#else
            gameplay_reset_state();
#if FREEWARE_EDITION == 10002
            menu_tracks(false);
#endif
#endif
            if (config_game_mode == 1 || config_game_mode == 2) {
                freeware_spawn_enabled = 1;
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION != 10002
            } else if (config_game_mode == 3) {
                creature_reset_all();
                freeware_spawn_enabled = 0;
                FIELD(freeware_level_number, level_number) = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
                G.reset_gameplay();
                G.load_next_level();
#else
                gameplay_reset_state();
                level_load_next();
#endif
                freeware_current_map->arm_triggers();
#endif
            }
            ACTIVE = 1;
        } else {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10002
            enter(3);
#else
            enter(FIELD(freeware_pause_perks, paused_perks) ? 4 : 3);
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
            G.paused = false;
#endif
        }
        break;
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION != 10002
    case 1:
        if (!ACTIVE) {
#ifdef CRIMSON_FREEWARE_CLIENT
            G.two_players = !G.two_players;
#endif
            config_player_count = 3 - config_player_count;
        }
        break;
#endif
    case 2:
        if (!ACTIVE) {
#if FREEWARE_EDITION == 10300
            int next = config_game_mode + 1;
            if (next > (FIELD(freeware_levels_sequence, levels_sequence) == 6 ? 3 : 2))
                next = 1;
            config_game_mode = (game_mode_id_t)next;
#ifdef CRIMSON_FREEWARE_CLIENT
            G.level_mode = next == 3 ? 3 : 0;
#endif
#else
            config_game_mode = (game_mode_id_t)(config_game_mode == 1 ? 2 : 1);
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10002
            set_label(freeware_main_labels + 1, config_game_mode == 1 ? "Game mode: career" : "Game mode: survival");
#endif
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
            G.survival = config_game_mode == 2;
#endif
        }
        break;
    case 3:
        request_transition();
        show_page(scores_page);
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION < 10400
        game_highscores_update();
#endif
        break;
    case 4:
        request_transition();
        show_page(credits_page);
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION < 10400
        game_credits_update();
#endif
        break;
    case 5:
        show_page(options_page);
        break;
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION >= 10400
    case 6:
        show_page(online_page);
        break;
#endif
    case 7:
#if FREEWARE_EDITION == 10002
        return false;
#else
        if (!ACTIVE)
            return false;
        menu_tracks(true);
        ACTIVE = 0;
        FIELD(freeware_logo_angle, logo_angle) = 0;
        MENU_MUSIC = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
        G.paused = false;
#endif
        break;
#endif
    }
    return true;
}
