// Inlined menu branches of game_frame_update (0x419663..0x41bd74).
enum menu_page { main_page, options_page, online_page, scores_page, credits_page };
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" {
extern int freeware_menu_selected, freeware_configuring, config_movement_schemes[2];
extern int freeware_tips_sequence, freeware_assembly_sequence;
extern unsigned char freeware_show_secret_hints, freeware_options_open, freeware_online_open, freeware_scores_open,
    freeware_credits_open, freeware_menu_music_pending, freeware_music_disabled, freeware_filter_sharp,
    freeware_show_fps, freeware_glow, freeware_smoke, freeware_shadows, freeware_shell_marks,
    freeware_direction_arrow, freeware_rebinding, freeware_calibrating, freeware_pause_perks;
extern char *freeware_main_labels[8], *freeware_option_labels[12], *freeware_online_labels[5];
void freeware_key_setup(), freeware_calibrate_pad(), game_credits_update(), game_highscores_update(),
    highscore_load_table(), freeware_online_action(int);
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
    if (freeware_online_open)
        return online_page;
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
        G.screen_started = G.menu_clock;
        break;
    case scores_page:
        G.screen = freeware::Screen::Scores;
        G.score_offset = 0;
        break;
    }
    G.notice = 0;
#else
    freeware_options_open = id == options_page;
    freeware_online_open = id == online_page;
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
#ifdef CRIMSON_FREEWARE_CLIENT
    if (!INPUT.ctrl)
        return;
#else
    if (!grim_interface_ptr->grim_is_key_down(0x1d))
        return;
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
}
__forceinline int menu_rows(int which) {
    const int count = which == main_page ? 8 : which == options_page ? 12 : 5;
    float x = (float)(screen_width / 2 - (which == main_page ? 100 : 140));
    int hover = -1;
    for (int i = 0; i < count; ++i) {
#ifdef CRIMSON_FREEWARE_CLIENT
        std::string label = which == main_page      ? freeware::menu_row(G, i).label
                            : which == options_page ? G.option(i)
                                                    : freeware::online_labels[i];
        const char *name = label.c_str();
        const float mx = G.cursor_x, my = G.cursor_y;
#else
        const char *name = which == main_page      ? freeware_main_labels[i]
                           : which == options_page ? freeware_option_labels[i]
                                                   : freeware_online_labels[i];
        const float mx = freeware_aim_screen.x, my = freeware_aim_screen.y;
#endif
        float y = which == main_page ? 200.f + i * 32.f : 170.f + i * 21.f;
        if (mx > x && my > y && mx < x + strlen(name) * 16.f && my < y + (which == main_page ? 30.f : 21.f))
            hover = i;
        float light = 1, alpha = hover == i ? .9f : SELECTED == i ? .7f : .6f;
        if ((which == main_page && ACTIVE && (i == 1 || i == 2)) || (which == online_page && i == 2)) {
            light = .6f;
            alpha = .4f;
        }
#ifdef CRIMSON_FREEWARE_CLIENT
        G.frame_labels.push_back(
            {name, x, y, which == options_page ? .65f : .75435f, {light, light, light, alpha}});
#else
        grim_interface_ptr->grim_set_color(light, light, light, alpha);
        grim_interface_ptr->grim_draw_text_mono(x, y, (char *)name);
#endif
    }
    if (menu_key(0xc8)) {
        --SELECTED;
        if (SELECTED < 0)
            SELECTED = 0;
    }
    if (menu_key(0xd0)) {
        ++SELECTED;
        if (SELECTED >= count)
            SELECTED = count - 1;
    }
    if (menu_key(0x1c))
        return SELECTED;
#ifdef CRIMSON_FREEWARE_CLIENT
    return INPUT.click ? hover : -1;
#else
    return grim_interface_ptr->grim_was_mouse_button_pressed(0) ? hover : -1;
#endif
}
__forceinline void menu_options(int row) {
    switch (row) {
    case 0:
        CONFIGURING = 1 - CONFIGURING;
        break;
    case 1:
#ifdef CRIMSON_FREEWARE_CLIENT
    {
        static const int next[] = {2, 0, 1};
        G.movement[CONFIGURING] = next[G.movement[CONFIGURING]];
    }
#else
        if (++config_movement_schemes[CONFIGURING] > 3)
            config_movement_schemes[CONFIGURING] = 1;
#endif
    break;
    case 2: {
        int &aim = FIELD(config_aim_schemes[CONFIGURING], aiming[CONFIGURING]);
        if (++aim > 3)
            aim = 0;
    } break;
    case 3:
#ifdef CRIMSON_FREEWARE_CLIENT
        G.music_enabled = !G.music_enabled;
#else
        freeware_music_disabled = !freeware_music_disabled;
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
        show_page(main_page);
        SELECTED = 0;
        break;
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    G.save_options();
#endif
}
__forceinline bool main_menu() {
    menu_secrets();
    int which = page();
    if (which != scores_page && MENU_MUSIC && !ACTIVE) {
        MENU_MUSIC = 0;
        STATE_SINCE = CLOCK;
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    if (G.rebind >= 0 || G.calibration >= 0 || which == scores_page || which == credits_page) {
        G.update_ui(INPUT);
        return true;
    }
    if (INPUT.escape && which != main_page) {
        show_page(main_page);
        SELECTED = 0;
        return true;
    }
#else
    if (freeware_rebinding) {
        freeware_key_setup();
        return true;
    }
    if (freeware_calibrating) {
        freeware_calibrate_pad();
        return true;
    }
    if (which == scores_page) {
        game_highscores_update();
        return true;
    }
    if (which == credits_page) {
        game_credits_update();
        return true;
    }
#endif
    int row = menu_rows(which);
    if (row < 0)
        return true;
    if (which == options_page) {
        menu_options(row);
        return true;
    }
    if (which == online_page) {
        if (row == 4) {
            show_page(main_page);
            SELECTED = 0;
        }
#ifdef CRIMSON_FREEWARE_CLIENT
        else if (row == 0)
            G.visit_website = true;
        else if (row == 1)
            G.notice = "Installed version: 1.4.0. The 2002 update service is unavailable.";
#else
        else if (row == 0 || row == 1)
            freeware_online_action(row);
#endif
        return true;
    }
    switch (row) {
    case 0:
        if (!ACTIVE) {
            enter(3);
#ifdef CRIMSON_FREEWARE_CLIENT
            G.start();
#else
            gameplay_reset_state();
            ACTIVE = 1;
            freeware_spawn_enabled = config_game_mode != 3;
#endif
            MENU_MUSIC = 1;
        } else {
            enter(FIELD(freeware_pause_perks, paused_perks) ? 4 : 3);
#ifdef CRIMSON_FREEWARE_CLIENT
            G.paused = false;
            G.resumed_this_frame = true;
#endif
        }
        break;
    case 1:
        if (!ACTIVE) {
#ifdef CRIMSON_FREEWARE_CLIENT
            G.two_players = !G.two_players;
#endif
            config_player_count = 3 - config_player_count;
        }
        break;
    case 2:
        if (!ACTIVE) {
            config_game_mode = (game_mode_id_t)(config_game_mode == 1 ? 2 : 1);
#ifdef CRIMSON_FREEWARE_CLIENT
            G.survival = config_game_mode == 2;
#endif
        }
        break;
    case 3:
        show_page(scores_page);
        break;
    case 4:
        show_page(credits_page);
        break;
    case 5:
        show_page(options_page);
        break;
    case 6:
        show_page(online_page);
        break;
    case 7:
        if (!ACTIVE)
            return false;
        ACTIVE = 0;
        MENU_MUSIC = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
        G.paused = false;
#endif
        break;
    }
    return true;
}
