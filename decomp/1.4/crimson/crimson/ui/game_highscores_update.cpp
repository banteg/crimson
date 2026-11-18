#include "overlay.h"
#include "freeware_edition.h"
#ifndef CRIMSON_FREEWARE_CLIENT
#include "../highscore/freeware_score.h"
#endif
#include <stdio.h>
#include <string.h>

using namespace ui140;

extern "C" {
extern unsigned char freeware_score_highlighted, freeware_scores_closing, freeware_score_corrupt;
extern float freeware_score_scroll, freeware_mouse_dy;
#ifndef CRIMSON_FREEWARE_CLIENT
extern freeware_score_entry freeware_last_score;
unsigned char highscore_load_table();
char *highscore_build_path();
__declspec(dllimport) int __stdcall DeleteFileA(const char *);
#endif
}

#if FREEWARE_EDITION < 10400
static inline void draw_score_heading(game_mode_id_t mode, float first_y, int &row) {
    if (mode == 2)
        text(50, first_y + row++ * 18, "-SURVIVAL--");
    else
        text(50, first_y + row++ * 18, "-CAREER----");
}
#endif

extern "C" unsigned char game_highscores_update() {
    filter(3);
#if FREEWARE_EDITION == 10002
    frame_dt = raw_delta(.8f);
    if (UI_PENDING) {
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.load_scores();
#endif
        reset_overlay_time();
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    if (freeware_frame_input->space_down)
#else
    if (grim_interface_ptr->grim_is_key_down(0x39))
#endif
        UI_PENDING = 1;
    float time = freeware_simulation_clock - UI_SINCE;
#else
    frame_dt = raw_delta();
    if (UI_PENDING) {
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.load_scores();
#else
        highscore_load_table();
#endif
        reset_overlay_time();
#if FREEWARE_EDITION >= 10400
        UI_FIELD(freeware_score_highlighted, score_highlighted) = 0;
#endif
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    const int board = (UI_GAME.survival ? 2 : 0) + (int)UI_GAME.two_players;
    bool corrupt = UI_GAME.invalid_scores[board];
#else
    bool corrupt = freeware_score_corrupt != 0;
#endif
    if (corrupt && key_pressed(0x20)) {
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.discard_corrupt_score();
#else
        DeleteFileA(highscore_build_path());
#endif
        UI_ALPHA = .99f;
    }
    float time = (freeware_simulation_clock - UI_SINCE) * 1.2f;
#endif
    backdrop(time, false);
#if FREEWARE_EDITION >= 10300
    float &scroll = UI_FIELD(freeware_score_scroll, score_scroll);
    scroll += UI_FIELD(freeware_mouse_dy, mouse_dy) * .5f;
#ifdef CRIMSON_FREEWARE_CLIENT
    if (freeware_frame_input->arrow_down)
        scroll += frame_dt * 5;
    if (freeware_frame_input->arrow_up)
        scroll -= frame_dt * 5;
#else
    if (grim_interface_ptr->grim_is_key_down(0xd0))
        scroll += frame_dt * 5;
    if (grim_interface_ptr->grim_is_key_down(0xc8))
        scroll -= frame_dt * 5;
#endif
    time += scroll;
#endif
    draw_backdrop();
#if FREEWARE_EDITION == 10002
    float top = viewport_height() - time * 17;
#define SCORE_TOP top
#else
    float travel = time * 17;
#define SCORE_TOP (viewport_height() - travel)
#endif
#define SCORE_Y(offset) (SCORE_TOP + (offset))
    int row = 0;
    text(50, SCORE_Y(row++ * 18), "Highscores:");
#if FREEWARE_EDITION >= 10400
    if (config_player_count == 2) {
        if (config_game_mode == 2)
            text(50, SCORE_Y(row++ * 18), "-SURVIVAL2-");
        else
            text(50, SCORE_Y(row++ * 18), "-CAREER2---");
    } else {
        if (config_game_mode == 2)
            text(50, SCORE_Y(row++ * 18), "-SURVIVAL--");
        else
            text(50, SCORE_Y(row++ * 18), "-CAREER----");
    }
#else
    draw_score_heading(config_game_mode, SCORE_TOP, row);
#endif
    ++row;
    for (int i = 0; i < 100; ++i) {
#ifdef CRIMSON_FREEWARE_CLIENT
#define SCORE_NAME name
#define SCORE_VALUE value
#define SCORE_VERSION version
        const char *name = "10tons";
        int value = 0;
#if FREEWARE_EDITION == 10300
        float version = 0;
#endif
#if FREEWARE_EDITION > 10002
        if (corrupt) {
            name = " ";
            if (i == 0)
                name = "Corrupted high score file.";
            else if (i == 1)
                name = "  (delete *.top files)";
            else if (i == 2)
                name = "(or press D to do it now)";
        } else
#endif
        if (i < (int)UI_GAME.scores().size()) {
            const freeware::Score &entry = UI_GAME.scores()[i];
            name = entry.name.c_str();
            value = config_game_mode == 2 ? entry.seconds : entry.experience;
#if FREEWARE_EDITION == 10300
            version = entry.version;
#endif
        }
#else
#define SCORE_NAME freeware_score_table[i].name
#define SCORE_VALUE freeware_score_table[i].value
#if FREEWARE_EDITION == 10300
#define SCORE_VERSION freeware_score_table[i].version
#endif
#endif
#if FREEWARE_EDITION == 10300
        if (config_game_mode != 2) {
            if (SCORE_VALUE > 50000 &&
                (SCORE_VERSION == 1.22f || SCORE_VERSION == 1.24f)) {
                if (UI_ALPHA < 1)
                    tint(1, .7f, .7f, UI_ALPHA * .88f);
                else
                    tint(1, .7f, .7f, .88f);
            } else {
                if (UI_ALPHA < 1)
                    tint(1, 1, 1, UI_ALPHA * .88f);
                else
                    tint(1, 1, 1, .88f);
            }
        }
#elif FREEWARE_EDITION >= 10400
        if (UI_ALPHA < 1) {
            tint(1, 1, 1, UI_ALPHA * .88f);
        } else if (config_game_mode != 2) {
            if (!UI_FIELD(freeware_score_highlighted, score_highlighted) &&
                UI_FIELD(freeware_last_score.value, last_score.experience) == SCORE_VALUE &&
                !strcmp(UI_FIELD(freeware_last_score.name, last_score.name.c_str()), SCORE_NAME)) {
                tint(.2f, .5f, 1, .98f);
                UI_FIELD(freeware_score_highlighted, score_highlighted) = 1;
            } else {
                tint(1, 1, 1, .88f);
            }
        } else {
            if (!UI_FIELD(freeware_score_highlighted, score_highlighted) &&
                UI_FIELD(freeware_last_score.seconds, last_score.seconds) == SCORE_VALUE &&
                !strcmp(UI_FIELD(freeware_last_score.name, last_score.name.c_str()), SCORE_NAME) &&
                UI_FIELD(freeware_last_score.value, last_score.experience)) {
                tint(.2f, .5f, 1, .98f);
                UI_FIELD(freeware_score_highlighted, score_highlighted) = 1;
            } else {
                tint(1, 1, 1, .88f);
            }
        }
        float y = SCORE_Y(row * 18);
        if (y <= viewport_height() && y >= -32)
#endif
        {
            char buffer[32];
            sprintf(buffer, "%d", i + 1);
            text(30, SCORE_Y(row * 18), buffer);
            text(80, SCORE_Y(row * 18), SCORE_NAME);
            sprintf(buffer, "%d", SCORE_VALUE);
            text(460, SCORE_Y(row * 18), buffer);
        }
        ++row;
    }
#undef SCORE_NAME
#undef SCORE_VALUE
#undef SCORE_VERSION
    bool past_end = SCORE_Y(row * 18) < 0;
#undef SCORE_Y
#undef SCORE_TOP
    if (UI_ALPHA < 1) {
        UI_FIELD(freeware_scores_closing, scores_closing) = 1;
        UI_ALPHA -= frame_dt * 2.4f;
    }
    if (key_pressed(1) || key_pressed(0x1c) || left_click() || past_end)
        UI_ALPHA -= frame_dt;
    if (UI_ALPHA <= 0) {
        set_state(1);
        UI_SINCE = freeware_simulation_clock;
        UI_PENDING = 1;
#ifndef CRIMSON_FREEWARE_CLIENT
        freeware_scores_open = 0;
#endif
        UI_FIELD(freeware_scores_closing, scores_closing) = 0;
#if FREEWARE_EDITION >= 10300
        scroll = 0;
#endif
    }
    return 1;
}
