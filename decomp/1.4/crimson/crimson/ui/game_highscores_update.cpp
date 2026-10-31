// crimson.exe 1.4.0, 0x41f480. The score loader copies Survival time into the display column.
#include "overlay.h"
#include <stdio.h>
#include <string.h>
using namespace ui140;
extern "C" {
extern float freeware_score_scroll, freeware_mouse_dy;
extern unsigned char freeware_score_highlighted, freeware_scores_closing, freeware_score_corrupt;
struct freeware_score_entry {
    char name[32];
    int seconds, value;
    float min_fps, average_fps, max_fps, version;
};
extern freeware_score_entry freeware_score_table[100], freeware_last_score;
void highscore_load_table();
char *highscore_build_path();
#ifndef CRIMSON_FREEWARE_CLIENT
__declspec(dllimport) int __stdcall DeleteFileA(const char *);
#endif
}
namespace {
__forceinline float row_y(float travel, int offset) { return (viewport_height() - travel) + offset; }
__forceinline bool scroll_key(int key) {
#ifdef CRIMSON_FREEWARE_CLIENT
    return key == 0xd0 ? freeware_frame_input->arrow_down : freeware_frame_input->arrow_up;
#else
    return grim_interface_ptr->grim_is_key_down((unsigned char)key) != 0;
#endif
}
} // namespace
extern "C" unsigned char game_highscores_update() {
    filter(3);
    frame_dt = raw_delta();
    if (UI_PENDING) {
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.load_scores();
#else
        highscore_load_table();
#endif
        reset_overlay_time();
        UI_FIELD(freeware_score_highlighted, score_highlighted) = 0;
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
    float elapsed = (freeware_simulation_clock - UI_SINCE) * 1.2f;
    backdrop(elapsed, false);
    float &scroll = UI_FIELD(freeware_score_scroll, score_scroll);
    scroll += UI_FIELD(freeware_mouse_dy, mouse_dy) * .5f;
    if (scroll_key(0xd0))
        scroll += frame_dt * 5;
    if (scroll_key(0xc8))
        scroll -= frame_dt * 5;
    float travel = (elapsed + scroll) * 17.f;
    draw_backdrop();

    text(50, row_y(travel, 0), "Highscores:");
    if (config_player_count == 2)
        text(50, row_y(travel, 18), config_game_mode == 2 ? "-SURVIVAL2-" : "-CAREER2---");
    else
        text(50, row_y(travel, 18), config_game_mode == 2 ? "-SURVIVAL--" : "-CAREER----");
    for (int i = 0; i < 100; ++i) {
#ifdef CRIMSON_FREEWARE_CLIENT
        const char *name = "10tons";
        int value = 0;
        if (corrupt) {
            name = " ";
            if (i == 0)
                name = "Corrupted high score file.";
            else if (i == 1)
                name = "  (delete *.top files)";
            else if (i == 2)
                name = "(or press D to do it now)";
        } else if (i < (int)UI_GAME.scores().size()) {
            const freeware::Score &entry = UI_GAME.scores()[i];
            name = entry.name.c_str();
            value = config_game_mode == 2 ? entry.seconds : entry.experience;
        }
        const char *last_name = UI_GAME.last_score.name.c_str();
        int last_xp = UI_GAME.last_score.experience, last_time = UI_GAME.last_score.seconds;
#else
        const char *name = freeware_score_table[i].name, *last_name = freeware_last_score.name;
        int value = freeware_score_table[i].value, last_xp = freeware_last_score.value,
            last_time = freeware_last_score.seconds;
#endif
        if (UI_ALPHA < 1)
            tint(1, 1, 1, UI_ALPHA * .88f);
        else if (!UI_FIELD(freeware_score_highlighted, score_highlighted) &&
                 value == (config_game_mode == 2 ? last_time : last_xp) && !strcmp(name, last_name) &&
                 (config_game_mode != 2 || last_xp)) {
            tint(.2f, .5f, 1, .98f);
            UI_FIELD(freeware_score_highlighted, score_highlighted) = 1;
        } else
            tint(1, 1, 1, .88f);
        float y = row_y(travel, 54 + i * 18);
        if (y <= viewport_height() && y >= -32) {
            char buffer[32];
            sprintf(buffer, "%d", i + 1);
            text(30, row_y(travel, 54 + i * 18), buffer);
            text(80, row_y(travel, 54 + i * 18), name);
            sprintf(buffer, "%d", value);
            text(460, row_y(travel, 54 + i * 18), buffer);
        }
    }
    if (UI_ALPHA < 1)
        UI_FIELD(freeware_scores_closing, scores_closing) = 1;
    if (dismiss_scroll(row_y(travel, 1854) < 0)) {
#ifndef CRIMSON_FREEWARE_CLIENT
        freeware_scores_open = 0;
#endif
        UI_FIELD(freeware_scores_closing, scores_closing) = 0;
        scroll = 0;
    }
    return 1;
}
