// The later freeware builds construct each page's hitboxes directly in the frame callback.
menu_secrets();
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
if (!freeware_scores_open && MENU_MUSIC && !ACTIVE) {
#else
int which = page();
if ((FREEWARE_EDITION == 10002 || which != scores_page) && MENU_MUSIC && !ACTIVE) {
#endif
    menu_tracks(true);
    MENU_MUSIC = 0;
    STATE_SINCE = CLOCK;
    FIELD(freeware_logo_angle, logo_angle) = 0;
}
#ifndef CRIMSON_FREEWARE_CLIENT
#if FREEWARE_EDITION >= 10300
refresh_labels(main_page);
#else
refresh_labels(which);
#endif
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
float age = CLOCK - STATE_SINCE;
float menu_clock = CLOCK;
menu_title(age, menu_clock);
#else
menu_title(which);
#endif
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION < 10300
bool overlay = which == scores_page || which == credits_page;
#ifdef CRIMSON_FREEWARE_CLIENT
if (FREEWARE_EDITION >= 10400 && !overlay && INPUT.escape && which != main_page) {
    show_page(main_page);
    SELECTED = 0;
    return true;
}
#endif
int row = -1;
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
if (!setup_controls()) {
    if (freeware_options_open) {
        refresh_option_labels();
        enum { which = options_page };
#include "frame_menu_rows.inc"
#if FREEWARE_EDITION >= 10400
    } else if (freeware_online_open) {
        enum { which = online_page };
#include "frame_menu_rows.inc"
#endif
    } else {
        enum { which = main_page };
#include "frame_menu_rows.inc"
    }
}
menu_footer_text();
cursor_particles(age, menu_clock);
if ((FREEWARE_EDITION == 10300 || !console_open_flag) && grim_interface_ptr->grim_is_key_down(0x1c))
    freeware_perk_hover = SELECTED;
if (!native_menu_actions())
    return 0;
if (freeware_credits_open)
    game_credits_update();
if (freeware_scores_open)
    game_highscores_update();
#else
if (overlay || !setup_controls())
    row = menu_rows(overlay ? main_page : which);
menu_footer_text();
cursor_particles(CLOCK - STATE_SINCE, CLOCK);
#endif
#if defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION < 10300
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
else if (which == options_page && FREEWARE_EDITION == 10002)
    row = freeware::option_action(row);
#else
row = native_menu_action(which, row);
#endif
if (which == options_page) {
    menu_options(row);
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION < 10400
    // Enter activates Done before the main menu reads the independent mouse edge.
    if (row == done_option && INPUT.accept && INPUT.click)
        row = 0;
    else
#endif
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
#if FREEWARE_EDITION == 10002
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
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10002
case 3:
case 4: {
    request_transition();
    show_page(row == 3 ? scores_page : credits_page);
    // The menu has consumed the click. Other edges still reach the overlay on its first frame.
    const freeware::Input *pressed = freeware_frame_input;
    freeware::Input remaining = *pressed;
    remaining.click = false;
    freeware_frame_input = &remaining;
    if (row == 3)
        game_highscores_update();
    else
        game_credits_update();
    freeware_frame_input = pressed;
} break;
#else
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
#endif
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
#endif
