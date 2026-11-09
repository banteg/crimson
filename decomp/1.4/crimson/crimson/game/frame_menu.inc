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
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
__forceinline void advance_secret(int &step, int required, int key) {
    if (step == required && menu_key(key))
        ++step;
}
#endif
__forceinline void menu_secrets() {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
    if (grim_interface_ptr->grim_is_key_down(0x1d)) {
        advance_secret(freeware_assembly_sequence, 0, 0x1e);
        advance_secret(freeware_assembly_sequence, 1, 0x1f);
        advance_secret(freeware_assembly_sequence, 2, 0x1f);
        advance_secret(freeware_assembly_sequence, 3, 0x12);
        advance_secret(freeware_assembly_sequence, 4, 0x32);
        advance_secret(freeware_assembly_sequence, 5, 0x30);
        advance_secret(freeware_assembly_sequence, 6, 0x26);
        if (freeware_assembly_sequence == 7 && menu_key(0x15)) {
            sfx_play_panned(17, .45f, .5f);
            ++freeware_assembly_sequence;
        }
    }
    if (grim_interface_ptr->grim_is_key_down(0x1d)) {
#if FREEWARE_EDITION == 10300
        advance_secret(freeware_levels_sequence, 0, 0x26);
        advance_secret(freeware_levels_sequence, 1, 0x12);
        advance_secret(freeware_levels_sequence, 2, 0x2f);
        advance_secret(freeware_levels_sequence, 3, 0x12);
        advance_secret(freeware_levels_sequence, 4, 0x26);
        if (freeware_levels_sequence == 5 && menu_key(0x1f)) {
            sfx_play_panned(17, .45f, .5f);
            ++freeware_levels_sequence;
        }
#else
        advance_secret(freeware_tips_sequence, 0, 0x14);
        advance_secret(freeware_tips_sequence, 1, 0x17);
        advance_secret(freeware_tips_sequence, 2, 0x19);
        if (freeware_tips_sequence == 3 && menu_key(0x1f)) {
            sfx_play_panned(17, .45f, .5f);
            freeware_show_secret_hints = 1;
        }
#endif
    }
#elif FREEWARE_EDITION != 10002
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
#if FREEWARE_EDITION == 10002
__forceinline void set_label(char **slot, const char *text) {
    crt_free(*slot);
    *slot = strdup_malloc(text);
}
#else
// The original reads each setting after releasing the label it owns.
template <typename T>
__forceinline void set_option_label(char *&label, const T &enabled, const char *on, const char *off) {
    crt_free(label);
    if (enabled)
        label = strdup_malloc(on);
    else
        label = strdup_malloc(off);
}
__forceinline void refresh_option_labels() {
    set_option_label(freeware_option_labels[0], CONFIGURING, "Configure for: Player 2", "Configure for: Player 1");

    crt_free(freeware_option_labels[1]);
    const int move = config_movement_schemes[CONFIGURING];
    if (move == 2)
        freeware_option_labels[1] = strdup_malloc("Control method: kb static");
    else if (move == 1)
        freeware_option_labels[1] = strdup_malloc("Control method: kb relative");
    else
        freeware_option_labels[1] = strdup_malloc(FREEWARE_EDITION == 10300 ? "Control method: joystic static"
                                                                   : "Control method: joystick static");

    crt_free(freeware_option_labels[2]);
    const int aim = config_aim_schemes[CONFIGURING];
#if FREEWARE_EDITION == 10300
    if (aim == 0)
        freeware_option_labels[2] = strdup_malloc("Aiming device: mouse");
    else if (aim == 1)
        freeware_option_labels[2] = strdup_malloc("Aiming device: keyboard");
    else
        freeware_option_labels[2] = strdup_malloc("Aiming device: joystick 'hat'");
#else
    if (aim == 0)
        freeware_option_labels[2] = strdup_malloc("Aiming device: mouse static");
    else if (aim == 1)
        freeware_option_labels[2] = strdup_malloc("Aiming device: mouse relative");
    else if (aim == 2)
        freeware_option_labels[2] = strdup_malloc("Aiming device: keyboard");
    else
        freeware_option_labels[2] = strdup_malloc("Aiming device: joystickk 'hat'");
#endif

    crt_free(freeware_option_labels[3]);
    if (freeware_music_disabled)
        freeware_option_labels[3] = strdup_malloc("Music: off");
#if FREEWARE_EDITION >= 10400
    else if (freeware_music_unavailable)
        freeware_option_labels[3] = strdup_malloc("Music: on (restart to enable playback)");
#endif
    else
        freeware_option_labels[3] = strdup_malloc("Music: on");
    set_option_label(freeware_option_labels[4], freeware_filter_sharp,
                     "Background filter: sharp", "Background filter: smooth");
    set_option_label(freeware_option_labels[5], freeware_show_fps, "Show FPS: on", "Show FPS: off");
    set_option_label(freeware_option_labels[6], freeware_glow,
                     "Glow, Smoke & Shadow FX: on", "Glow, Smoke & Shadow FX: off");
    set_option_label(freeware_option_labels[7], freeware_shell_marks, "Shell marks: on", "Shell marks: off");
#if FREEWARE_EDITION >= 10400
    set_option_label(freeware_option_labels[8], freeware_direction_arrow, "Direction Arrow: on", "Direction Arrow: off");
#endif
}
#endif
__forceinline void refresh_labels(int which) {
#if FREEWARE_EDITION >= 10300
    crt_free(freeware_main_labels[0]);
    if (ACTIVE)
        freeware_main_labels[0] = strdup_malloc("Resume game.");
    else
        freeware_main_labels[0] = strdup_malloc("Begin game.");
    crt_free(freeware_main_labels[1]);
    if (config_player_count == 1)
        freeware_main_labels[1] = strdup_malloc("Players: one");
    else
        freeware_main_labels[1] = strdup_malloc("Players: two");
    crt_free(freeware_main_labels[2]);
    if (config_game_mode == 1)
        freeware_main_labels[2] = strdup_malloc("Game mode: career");
    else if (config_game_mode == 2)
        freeware_main_labels[2] = strdup_malloc("Game mode: survival");
    else if (config_game_mode == 3)
        freeware_main_labels[2] = strdup_malloc("Game mode: Level Test");
    else
        freeware_main_labels[2] = strdup_malloc("Game mode: Level Edit");
    const int last = FREEWARE_EDITION == 10300 ? 6 : 7;
    crt_free(freeware_main_labels[last]);
    if (ACTIVE)
        freeware_main_labels[last] = strdup_malloc("End current game.");
    else
        freeware_main_labels[last] = strdup_malloc("End.");
#else
    set_label(freeware_main_labels, ACTIVE ? "Resume game." : "Begin game.");
    if (which != options_page)
        return;
    set_label(freeware_option_labels, config_movement_schemes[0] == 2 ? "Control method: static" : "Control method: relative");
    set_label(freeware_option_labels + 2, freeware_shadows ? "Shadows: on" : "Shadows: off");
    set_label(freeware_option_labels + 3, freeware_filter_sharp ? "Background filter: sharp" : "Background filter: smooth");
    set_label(freeware_option_labels + 4, freeware_show_fps ? "Show FPS: on" : "Show FPS: off");
    set_label(freeware_option_labels + 5, freeware_glow ? "Flame Glow FX: on" : "Flame Glow FX: off");
    set_label(freeware_option_labels + 6, freeware_shell_marks ? "Shell marks: on" : "Shell marks: off");
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
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION < 10300
__forceinline int menu_rows(int which) {
#include "frame_menu_rows.inc"
#if FREEWARE_EDITION == 10300
    if (INPUT.accept || INPUT.accept_down)
        hover = SELECTED;
    if (INPUT.accept)
        return hover;
#elif FREEWARE_EDITION == 10002
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
#endif
enum { rebind_option = FREEWARE_EDITION == 10300 ? 8 : 9, calibrate_option, done_option };
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
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10002
    if (row == 12 || row == 14)
        return;
    if (row == 13)
        G.shadows = !G.shadows;
#endif
    if (row == 0) {
        CONFIGURING = 1 - CONFIGURING;
    } else if (row == 1) {
#ifdef CRIMSON_FREEWARE_CLIENT
#if FREEWARE_EDITION == 10002
        G.movement[0] = 1 - G.movement[0];
#else
        static const int next[] = {2, 0, 1};
        G.movement[CONFIGURING] = next[G.movement[CONFIGURING]];
#endif
#else
        ++config_movement_schemes[CONFIGURING];
        if (config_movement_schemes[CONFIGURING] > 3)
            config_movement_schemes[CONFIGURING] = 1;
#endif
    } else if (row == 2) {
#ifdef CRIMSON_FREEWARE_CLIENT
        int &aim = G.aiming[CONFIGURING];
        if (FREEWARE_EDITION == 10300 && aim == 0)
            ++aim; // Slot 1 is the later relative-mouse option.
        if (++aim > 3)
            aim = 0;
#else
        ++config_aim_schemes[CONFIGURING];
        if (config_aim_schemes[CONFIGURING] > (FREEWARE_EDITION == 10300 ? 2 : 3))
            config_aim_schemes[CONFIGURING] = 0;
#endif
    } else if (row == 3) {
#ifdef CRIMSON_FREEWARE_CLIENT
        G.music_enabled = !G.music_enabled;
#else
        freeware_music_disabled = !freeware_music_disabled;
#if FREEWARE_EDITION == 10400
        if (!freeware_music_unavailable) {
            if (freeware_music_disabled) {
                freeware_music_stop(30);
                freeware_music_stop(29);
                freeware_music_stop(31);
            } else if (ACTIVE) {
                freeware_music_stop(30);
                freeware_music_stop(29);
                freeware_music_start(31);
            } else {
                freeware_music_stop(31);
                freeware_music_stop(29);
                freeware_music_start(30);
            }
        }
#elif FREEWARE_EDITION == 10300
        if (freeware_music_disabled) {
            freeware_title_track_fade();
            freeware_game_track_fade();
        } else if (ACTIVE)
            freeware_game_track_start(31);
        else
            freeware_title_track_start(30);
#endif
#endif
    } else if (row == 4) {
        FIELD(freeware_filter_sharp, smooth) = !FIELD(freeware_filter_sharp, smooth);
    } else if (row == 5) {
        FIELD(freeware_show_fps, show_fps) = !FIELD(freeware_show_fps, show_fps);
    } else if (row == 6) {
        FIELD(freeware_glow, effects) = !FIELD(freeware_glow, effects);
#ifndef CRIMSON_FREEWARE_CLIENT
        freeware_smoke = !freeware_smoke;
        freeware_shadows = !freeware_shadows;
#elif FREEWARE_EDITION != 10002
        G.smoke = !G.smoke;
        G.shadows = !G.shadows;
#endif
    } else if (row == 7) {
        FIELD(freeware_shell_marks, shell_marks) = !FIELD(freeware_shell_marks, shell_marks);
    } else if (FREEWARE_EDITION >= 10400 && row == 8) {
        FIELD(freeware_direction_arrow, direction_arrow) = !FIELD(freeware_direction_arrow, direction_arrow);
    } else if (row == rebind_option) {
#ifdef CRIMSON_FREEWARE_CLIENT
        G.rebind = 0;
#else
        freeware_rebinding = 1;
#endif
    } else if (row == calibrate_option) {
#ifdef CRIMSON_FREEWARE_CLIENT
        G.calibration = 0;
#else
        freeware_calibrating = 1;
#endif
    } else if (row == done_option) {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
        freeware_options_open = 0;
        freeware_perk_hover = 0;
#elif FREEWARE_EDITION == 10300
        show_page(main_page);
        G.perk_hover = 0;
#else
        show_page(main_page);
#if FREEWARE_EDITION == 10002
        G.perk_hover = 0;
#else
        SELECTED = 0;
#endif
#endif
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
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
__forceinline void menu_title(float age, float menu_clock) {
    if (freeware_assembly_sequence == 8) {
        frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("asmlogo"));
        menu_blend(true);
        grim_interface_ptr->grim_set_rotation(0);
        grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
        grim_interface_ptr->grim_begin_batch();

        vec2f_t center = {screen_width / 2 + cosf(age - .2f) * 5.f,
                          140.f + cosf(age - .2f) * 5.f};
        vec2f_t delta = {center.x - MOUSE_X, center.y - MOUSE_Y};
        float direction = atan2f(delta.y, delta.x);
        float length = sqrtf(delta.x * delta.x + delta.y * delta.y) * .02f;
        length *= 20.f;
        for (int i = 1; i < length; i += 3) {
            grim_interface_ptr->grim_set_color(.7f, .8f, 1, .09f - i * .09f / length);
            grim_interface_ptr->grim_draw_quad(center.x - 89.f + cosf(direction) * i,
                    center.y + sinf(direction) * i / 3.f, 178, 29);
        }
        grim_interface_ptr->grim_set_color(1, 1, 1, .7f);
        grim_interface_ptr->grim_draw_quad(center.x - 89.f, center.y, 178, 29);
        grim_interface_ptr->grim_end_batch();
    }
    if (freeware_birthday) {
#if FREEWARE_EDITION == 10300
        float wave = (float)(cos(age - .2f) * 5.f);
        grim_interface_ptr->grim_set_color(1, 1, 1, 1);
        grim_interface_ptr->grim_draw_text_mono(screen_width / 2 + wave - 100, wave + 170, "Happy birthday !");
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
            vec2f_t pos;
            pos.x = (float)x;
            grim_interface_ptr->grim_set_rotation(pos.x + (float)sin(age * .4f));
            float &y = freeware_snow_y[x];
            y += ((x * 34 % 5) + 1) * 5 * frame_dt;
            while (y > 150)
                y -= 200;
            pos.y = y;
            if (pos.y < 0)
                grim_interface_ptr->grim_set_color(1, 1, 1, 0);
            else if (pos.y < 50)
                grim_interface_ptr->grim_set_color(1, 1, 1, pos.y * .02f);
            else if (pos.y > 100)
                grim_interface_ptr->grim_set_color(1, 1, 1, 1 - (pos.y - 100) * .02f);
            else
                grim_interface_ptr->grim_set_color(1, 1, 1, 1);
            grim_interface_ptr->grim_draw_quad(pos.x, pos.y, 32, 32);
        }
        grim_interface_ptr->grim_end_batch();
    }
    if (freeware_memorial) {
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .6f);
        vec2f_t point = {screen_width / 2 + cosf(age - .2f) * 5.f - 100.f, cosf(age - .2f) * 5.f + 170.f};
        for (float d = 0; d < 16; d += .5f) {
            grim_interface_ptr->grim_set_config_var(frame_font_scale, .6f + (d / 16.f) * .05f);
            grim_interface_ptr->grim_set_color(.1f, .4f, .7f, (1.f - d / 16.f) * .2f);
            grim_interface_ptr->grim_draw_text_mono(point.x - cosf(age - .2f) * d,
                                                    point.y + sinf(age - .2f) * d * 2.f, "The World Grieves..");
        }
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .6f);
        grim_interface_ptr->grim_set_color(1, 1, 1, 1);
        grim_interface_ptr->grim_draw_text_mono(point.x, point.y, "The World Grieves..");
    }
    if (freeware_solstice) {
        vec2f_t point = {screen_width / 2 + cosf(age - .2f) * 5.f - 100.f,
                         cosf(age - .2f) * 5.f + 170.f};
        grim_interface_ptr->grim_set_color(1, 1, 1, .15f);
        frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("tl_tolmec"));
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_rotation(age * .2f);
        grim_interface_ptr->grim_draw_quad(100, 100, 256, 256);
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_color(1, .8f, .2f, 1);
        grim_interface_ptr->grim_draw_text_mono(point.x, point.y, "Have a Nice End of the World !");
    }
#endif

    if (age < 1.f)
        grim_interface_ptr->grim_set_color(1, 1, 1, age);
    else
        grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_set_config_var(0x12, true);
    vec2f_t base = {(float)(screen_width / 2), 90.f};
    vec2f_t center = base;
    center.x += (float)cos(menu_clock) * 5.f;
    center.y += (float)sin(menu_clock) * 5.f;
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
        center.x += freeware_logo_angle * 50.f;
        center.y -= freeware_logo_angle * 30.f;
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
    grim_interface_ptr->grim_draw_quad(center.x - 256.f, center.y - 64.f, 512.f, 512.f - freeware_logo_angle * 30.f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
}
#else
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
#endif

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
#if FREEWARE_EDITION == 10300
#define CALIBRATION_JOYSTICK "joystic"
#else
#define CALIBRATION_JOYSTICK "joystick"
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
__forceinline void calibration_prompt(char *message) {
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    grim_interface_ptr->grim_set_color(1, 1, 1, .6f);
    char *wrapped = wrap_text_to_width_alloc(message, 45);
    grim_interface_ptr->grim_draw_text_mono(50, 120, wrapped);
    crt_free(wrapped);
}
__forceinline void calibration_pov(char *message, int &direction) {
    calibration_prompt(message);
    if ((FREEWARE_EDITION == 10300 || !console_open_flag) && menu_key(0x1c)) {
        direction = grim_interface_ptr->grim_get_joystick_pov(0);
        ++freeware_setup_step;
    }
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
    sprintf(freeware_ui_buffer, "POV0 ('hat') status: %d", grim_interface_ptr->grim_get_joystick_pov(0));
    grim_interface_ptr->grim_draw_text_mono(40, 250, freeware_ui_buffer);
}
__forceinline void binding_prompt(int step, char *message) {
    if (freeware_setup_step == step)
        grim_interface_ptr->grim_draw_text_mono(120, 250, message);
}
__forceinline bool setup_controls() {
    if (freeware_rebinding) {
        label("Press down key for..", 50, 200, .85435f, 1, 1, 1, .6f);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
        binding_prompt(0, "Player 1 UP");
        binding_prompt(1, "Player 1 DOWN");
        binding_prompt(2, "Player 1 LEFT");
        binding_prompt(3, "Player 1 RIGHT");
        binding_prompt(4, "Player 1 FIRE");
        binding_prompt(5, "Player 2 UP");
        binding_prompt(6, "Player 2 DOWN");
        binding_prompt(7, "Player 2 LEFT");
        binding_prompt(8, "Player 2 RIGHT");
        binding_prompt(9, "Player 2 FIRE");
        for (int key = 0; key < 256; ++key) {
            if (menu_key(key)) {
                freeware_saved_keys[freeware_setup_step++] = (unsigned char)key;
                break;
            }
        }
        if (freeware_setup_step >= 10) {
            freeware_setup_step = 0;
            freeware_rebinding = 0;
            freeware_save_config();
            config_load_presets();
        }
        return true;
    }
    if (!freeware_calibrating)
        return false;

    grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
    if (freeware_setup_step == 0) {
        calibration_prompt("Center the " CALIBRATION_JOYSTICK " and press enter or a " CALIBRATION_JOYSTICK " button");
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
        sprintf(freeware_ui_buffer, "X-Axis: %d\nY-Axis: %d", grim_interface_ptr->grim_get_joystick_x(),
                grim_interface_ptr->grim_get_joystick_y());
        grim_interface_ptr->grim_draw_text_mono(40, 250, freeware_ui_buffer);
        if ((FREEWARE_EDITION == 10300 || !console_open_flag) && (menu_key(0x1c) || grim_interface_ptr->grim_is_joystick_button_down(0) ||
            grim_interface_ptr->grim_is_joystick_button_down(1) || grim_interface_ptr->grim_is_joystick_button_down(2) ||
            grim_interface_ptr->grim_is_joystick_button_down(3) || grim_interface_ptr->grim_is_joystick_button_down(4))) {
            freeware_pad_center_x = grim_interface_ptr->grim_get_joystick_x();
            freeware_pad_center_y = grim_interface_ptr->grim_get_joystick_y();
            ++freeware_setup_step;
        }
    } else if (freeware_setup_step == 1) {
        calibration_prompt("Set the " CALIBRATION_JOYSTICK " X/Y-Axis threshold with arrow keys up/down, press enter when done.");
        if (FREEWARE_EDITION == 10300 || !console_open_flag) {
            if (menu_key(0xc8))
                freeware_pad_threshold += 10;
            if (menu_key(0xd0))
                freeware_pad_threshold -= 10;
            if (menu_key(0x1c))
                ++freeware_setup_step;
        }
        if (freeware_pad_threshold < 0)
            freeware_pad_threshold = 0;
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .70435f);
        sprintf(freeware_ui_buffer, "X/Y-Axis threshold: %d", freeware_pad_threshold);
        grim_interface_ptr->grim_draw_text_mono(40, 250, freeware_ui_buffer);
        sprintf(freeware_ui_buffer, "Status:\n\nUp: %d\nDown: %d\nLeft: %d\nRight: %d", input_move_up_active(),
                input_move_down_active(), input_move_left_active(), input_move_right_active());
        grim_interface_ptr->grim_draw_text_mono(40, 300, freeware_ui_buffer);
    } else if (freeware_setup_step == 2)
        calibration_pov("If your " CALIBRATION_JOYSTICK " has 'hat' press it LEFT now and press enter. (press enter to skip this)", freeware_pov_left);
    else if (freeware_setup_step == 3)
        calibration_pov("If your " CALIBRATION_JOYSTICK " has 'hat' press it RIGHT now and press enter. (press enter to skip this)", freeware_pov_right);
    else if (freeware_setup_step >= 4) {
        freeware_setup_step = 0;
        freeware_calibrating = 0;
        freeware_save_config();
        config_load_presets();
    }
    return true;
}
#else
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
        // The 1.3.0 wizard always polls Grim's one joystick, including while editing player two.
        const int pad = FREEWARE_EDITION == 10300 ? 0 : CONFIGURING;
        int x = (int)(1000 * INPUT.stick_x[pad]), y = (int)(1000 * INPUT.stick_y[pad]);
        int threshold = (int)(G.pad_threshold[pad] * 1000 + .5f);
        float ax = INPUT.aim_x[pad], ay = INPUT.aim_y[pad];
        int pov = ax == 0 && ay == 0 ? -1 : (int)(atan2(ax, -ay) * 5729.5779513 + 36000.5) % 36000;
#else
        int x = grim_interface_ptr->grim_get_joystick_x(), y = grim_interface_ptr->grim_get_joystick_y();
        int &threshold = freeware_pad_threshold;
        int pov = grim_interface_ptr->grim_get_joystick_pov(0);
#endif
        const char *prompts[] = {
            "Center the " CALIBRATION_JOYSTICK " and press enter or a " CALIBRATION_JOYSTICK " button",
            "Set the " CALIBRATION_JOYSTICK " X/Y-Axis threshold with arrow keys up/down, press enter when done.",
            "If your " CALIBRATION_JOYSTICK " has 'hat' press it LEFT now and press enter. (press enter to skip this)",
            "If your " CALIBRATION_JOYSTICK " has 'hat' press it RIGHT now and press enter. (press enter to skip this)"};
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
            bool trigger = INPUT.pad_any[pad];
#else
            bool trigger = false;
            for (int j = 0; j < 5; ++j)
                if (grim_interface_ptr->grim_is_joystick_button_down(j))
                    trigger = true;
#endif
            if (menu_key(0x1c) || trigger) {
#ifdef CRIMSON_FREEWARE_CLIENT
                G.pad_center[pad].x = x * .001f;
                G.pad_center[pad].y = y * .001f;
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
            G.pad_threshold[pad] = threshold * .001f;
#endif
            sprintf(status, "X/Y-Axis threshold: %d", threshold);
            if (menu_key(0x1c))
                ++step;
        } else {
            sprintf(status, "POV0 ('hat') status: %d", pov);
            if (menu_key(0x1c)) {
#ifdef CRIMSON_FREEWARE_CLIENT
                if (step == 2)
                    G.pad_left_pov[pad] = pov;
                else
                    G.pad_right_pov[pad] = pov;
#else
                if (step == 2)
                    freeware_pov_left = pov;
                else
                    freeware_pov_right = pov;
#endif
                ++step;
            }
        }
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
        // Both players read the same four calibrated values in the original.
        G.pad_center[1] = G.pad_center[0];
        G.pad_threshold[1] = G.pad_threshold[0];
        G.pad_left_pov[1] = G.pad_left_pov[0];
        G.pad_right_pov[1] = G.pad_right_pov[0];
#endif
        label(status, 40, 250, .70435f, 1, 1, 1, .6f);
        if (display_step == 1) {
#ifdef CRIMSON_FREEWARE_CLIENT
            int dx = x - (int)(G.pad_center[pad].x * 1000),
                dy = y - (int)(G.pad_center[pad].y * 1000);
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
#endif
#undef CALIBRATION_JOYSTICK
__forceinline void cursor_particles(float pulse, float orbit) {
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION < 10300
    float x = MOUSE_X - 32, y = MOUSE_Y - 32;
#endif
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_set_config_var(frame_src_blend, 5u);
    grim_interface_ptr->grim_set_config_var(frame_dst_blend, 2u);
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("part"));
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_begin_batch();
#if FREEWARE_EDITION >= 10300
    grim_interface_ptr->grim_draw_quad(MOUSE_X - 32.f, MOUSE_Y - 32.f, 64, 64);
#else
    grim_interface_ptr->grim_draw_quad(x, y, 64, 64);
#endif
#else
    G.ui.destination_blend = 2;
    const float rotation = G.frame_sprites.empty() ? 0 : G.frame_sprites.back().angle;
    sprite("part", x, y, 64, 64, rotation, 1, 1, 1, 1);
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
    float alpha = ((float)pow((float)cos(pulse), 2) + 1.f) * .5f;
#else
    float alpha = (float)((pow(cos(pulse), 2) + 1) * .5);
#endif
    for (int step = 0; step < 6; step += 2) {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
        grim_interface_ptr->grim_set_color(1, 1, 1, alpha);
        float angle = orbit + step * 1.0471976f;
        grim_interface_ptr->grim_draw_quad(MOUSE_X - 32.f + (float)cos(angle) * 16.f,
                                           MOUSE_Y - 32.f + (float)sin(angle) * 16.f, 64, 64);
#else
        double angle = orbit + (double)step * 1.0471976f;
        float px = (float)(x + cos(angle) * 16), py = (float)(y + sin(angle) * 16);
#ifdef CRIMSON_FREEWARE_CLIENT
        sprite("part", px, py, 64, 64, rotation, 1, 1, 1, alpha);
#else
        grim_interface_ptr->grim_set_color(1, 1, 1, alpha);
        grim_interface_ptr->grim_draw_quad(px, py, 64, 64);
#endif
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
__forceinline void menu_footer_text() {
#ifdef CRIMSON_FREEWARE_CLIENT
    const char *version = FREEWARE_EDITION == 10002 ? "v " FREEWARE_VERSION : "v" FREEWARE_VERSION;
#else
    const char *version = FREEWARE_EDITION == 10002 ? "v 1.0.2" : FREEWARE_EDITION == 10300 ? "v1.3.0" : "v1.4.0";
#endif
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .65435f);
    grim_interface_ptr->grim_set_color(1, 1, 1, .4f);
    grim_interface_ptr->grim_draw_text_mono(10, (float)screen_height - 25, (char *)version);
    grim_interface_ptr->grim_draw_text_mono(FREEWARE_EDITION >= 10300 ? (float)(screen_width - 330) : (float)screen_width - 330,
                                            (float)screen_height - 25, "2002 (c) 10tons entertainment");
#else
    label(version, 10, (float)screen_height - 25, .65435f, 1, 1, 1, .4f);
    label("2002 (c) 10tons entertainment", (float)screen_width - 330, (float)screen_height - 25, .65435f, 1, 1, 1,
          .4f);
#endif
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
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
__forceinline bool menu_clicked() {
    return (FREEWARE_EDITION == 10300 || !console_open_flag) &&
           (grim_interface_ptr->grim_was_key_pressed(0x1c) || grim_interface_ptr->grim_was_mouse_button_pressed(0));
}
__forceinline bool native_menu_actions() {
    if (freeware_options_open && menu_clicked())
        menu_options(freeware_perk_hover);
    if (FREEWARE_EDITION >= 10400 && freeware_online_open && menu_clicked()) {
        if (freeware_perk_hover == 0) {
            freeware_open_site = 1;
            quit_requested = 1;
        } else if (freeware_perk_hover == 1) {
            freeware_http_response *response = freeware_http_get("www.mbnet.fi", "~temper/crimsonland", "versioninfo.txt");
            if (response) {
                crt_free(freeware_update_info);
                freeware_update_info = response->data;
            }
        } else if (freeware_perk_hover == 4) {
            freeware_online_open = 0;
            freeware_perk_hover = 0;
        }
    }
    if (!freeware_credits_open && !freeware_scores_open && !freeware_options_open &&
        (FREEWARE_EDITION == 10300 || !console_open_flag) &&
        (grim_interface_ptr->grim_was_mouse_button_pressed(0) || grim_interface_ptr->grim_was_key_pressed(0x1c))) {
        if (freeware_perk_hover == 0) {
            if (ACTIVE)
                enter(freeware_pause_perks ? 4 : 3);
            else {
                freeware_logo_visible = 0;
                MENU_MUSIC = 1;
                enter(3);
                freeware_music_started = 1;
                menu_tracks(false);
                freeware_current_map->clear();
                gameplay_reset_state();
                if (config_game_mode == 1)
                    freeware_spawn_enabled = 1;
                else if (config_game_mode == 2)
                    freeware_spawn_enabled = 1;
                else if (config_game_mode == 3) {
                    creature_reset_all();
                    freeware_spawn_enabled = 0;
                    freeware_level_number = 0;
                    gameplay_reset_state();
                    level_load_next();
                    freeware_current_map->arm_triggers();
                }
                ACTIVE = 1;
            }
        } else if (freeware_perk_hover == 1) {
            if (!ACTIVE)
                config_player_count = 3 - config_player_count;
        } else if (freeware_perk_hover == 2) {
            if (!ACTIVE) {
                config_game_mode = (game_mode_id_t)(config_game_mode + 1);
                if (freeware_levels_sequence == 6) {
                    if (config_game_mode > 3)
                        config_game_mode = (game_mode_id_t)1;
                } else if (config_game_mode > 2)
                    config_game_mode = (game_mode_id_t)1;
            }
        } else if (freeware_perk_hover == 3) {
            highscore_load_table();
            freeware_transition_pending = 1;
            freeware_scores_open = 1;
            freeware_transition_alpha = 1;
        } else if (freeware_perk_hover == 4) {
            freeware_transition_pending = 1;
            freeware_credits_open = 1;
            freeware_transition_alpha = 1;
        } else if (freeware_perk_hover == 5)
            freeware_options_open = 1;
        else if (FREEWARE_EDITION >= 10400 && freeware_perk_hover == 6)
            freeware_online_open = 1;
        else if (freeware_perk_hover == (FREEWARE_EDITION == 10300 ? 6 : 7)) {
            if (!ACTIVE)
                return false;
            menu_tracks(true);
            ACTIVE = 0;
            freeware_logo_angle = 0;
            MENU_MUSIC = 0;
        }
    }
    if (freeware_credits_open)
        game_credits_update();
    if (freeware_scores_open)
        game_highscores_update();
    return true;
}
#endif
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION < 10300
__forceinline bool main_menu() {
#include "frame_main_menu.inc"
}
#endif
