// Inlined in the 1.0.2 playing state at 0x40dab9..0x40e411.
#ifndef GAMEPLAY_HUD_102_H
#define GAMEPLAY_HUD_102_H
#include "freeware_ui.h"
#include <stdio.h>

extern "C" void freeware_hud_set_row(int);

namespace hud102 {
__forceinline bool render() {
    using namespace ui140;
#ifdef CRIMSON_FREEWARE_CLIENT
    char output[80];
#else
    char *output = freeware_ui_buffer;
#endif
    filter(1);
    tint(.7f, .7f, .7f, 1);
    bind("bar");
    begin();
    uv(0, 0, 1, 1);
    angle(0);
    quad(0, 0, 640, 64);
    end();

    if (config_game_mode == 1) {
        scale(1.f);
        tint(1, 1, 1, .7f);
#ifdef CRIMSON_FREEWARE_CLIENT
        bind("bullet_i");
#else
        bind(freeware_bullet_icon);
#endif
        begin();
        angle(0);
        int column;
        for (column = 0; column < (int)UI_PLAYER(current_player_index).ammo; ++column)
            quad(320 + column * 10.f, 10, 16, 22);
        tint(1, 1, 1, .3f);
        for (column = (int)UI_PLAYER(current_player_index).ammo; column < (int)UI_PLAYER(current_player_index).clip_size && column < 30; ++column)
            quad(320 + column * 10.f, 10, 16, 22);
        end();
    }

    filter(2);
    angle(0);
    bind("bullet");
    uv(0, 0, 1, 1);
    tint(.4f, .4f, .4f, .8f);
    begin();
    quad(10, 35, 140, 15);
    tint(.38f, .04f, .04f, .9f);
    float hp = UI_FIELD(UI_PLAYER(current_player_index).health, actor(current_player_index).health) * .01f;
    if (hp > 1)
        hp = 1;
    if (hp > 0)
        quad(12, 37, 12 + hp * 124, 11);
    end();
    tint(1, 1, 1, 1);
    if (UI_FIELD(UI_PLAYER(current_player_index).health, actor(current_player_index).health) <= 0) {
        UI_FIELD(UI_PLAYER(current_player_index).health, actor(current_player_index).health) = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
        UI_GAME.enter_state(6);
        UI_GAME.death_clock = 0;
#else
        game_state_id = 6;
#endif
        UI_FIELD(freeware_transition_pending, transition_pending) = 1;
        UI_FIELD(freeware_transition_alpha, transition_alpha) = 1;
        UI_FIELD(freeware_state_since, state_since) = freeware_simulation_clock;
    }

    if (config_game_mode == 1) {
        filter(1);
        tint(1, 1, 1, 1);
        bind("ui_text");
        angle(0);
        begin();
        freeware_hud_set_row(2);
        quad(-3, -6, 256, 50);
        end();
        filter(2);
        tint(1, 1, 1, .7f);
        scale(.7f);
        sprintf(output, "%d", UI_FIELD(UI_PLAYER(current_player_index).experience, run.experience));
        tint(0, 0, 0, 1);
        text(220, 7, output);
        tint(.8f, .1f, .1f, 1);
        text(220, 7, output);
    } else if (config_game_mode == 2) {
        tint(1, 1, 1, .7f);
        scale(.7f);
        if (UI_FIELD(game_state_id, frame_state()) != 6)
            UI_FIELD(freeware_elapsed_seconds, run.seconds) += frame_dt;
#ifdef CRIMSON_FREEWARE_CLIENT
        freeware_elapsed_seconds = UI_GAME.run.seconds;
#endif
        sprintf(output, "Seconds survived: %d", (int)freeware_elapsed_seconds);
        tint(0, 0, 0, 1);
        // Native draws the time twice in black and three times in red.
        text(220, 5, output);
        text(220, 5, output);
        tint(.6f, .01f, .01f, 1);
        text(220, 5, output);
        text(220, 5, output);
        text(220, 5, output);
        UI_PLAYER(current_player_index).ammo = 30.f;
    }

    tint(1, 1, 1, 1);
    uv(0, 0, 1, 1);
    filter(2);
    const int weapon = UI_PLAYER(current_player_index).weapon;
    if (weapon == 1)
        text(15, 60, "Pistol");
    else if (weapon == 2)
        text(15, 60, "AutoRifle");
    else if (weapon == 3)
        text(15, 60, "Shotgun");
    else if (weapon == 4)
        text(15, 60, "Flamethrower");
    else if (weapon == 5)
        text(15, 60, "High RPM Rifle");
    else if (weapon == 6)
        text(15, 60, "Plasma Rifle");
    else if (weapon == 7)
        text(15, 60, "Plasma Rifle (twin mode)");
    else if (weapon == 8)
        text(15, 60, "Plasma Minigun");
    else
        text(15, 60, "Unknown");

    if (UI_FIELD(freeware_pending_perks, run.pending) >= 1 && config_game_mode != 2) {
        tint(.9f, .8f, .1f, .7f);
        scale(.6f);
        filter(1);
        tint(1, 1, 1, 1);
        bind("ui_text");
        angle(0);
        begin();
        freeware_hud_set_row(0);
        quad(400, 430, 256, 50);
        end();
        filter(2);
        return true;
    }
    return false;
}
} // namespace hud102
#endif
