// crimson.exe 1.4.0, 0x416a00.
#include "freeware_ui.h"
#include <stdio.h>
using namespace ui140;
extern "C" {
extern int perk_id_ammo_maniac;
extern float freeware_hud_xp_timer;
void freeware_hud_set_row(int);
}
namespace {
#define P(i) player_state_table[i].freeware
#define HEALTH(i) UI_FIELD(P(i).health, actor(i).health)
__forceinline void rounds(float multiplier, float y, float h) {
    float spacing = 1;
    if (P(current_player_index).clip_size * multiplier > 30)
        spacing = 30 / (P(current_player_index).clip_size * multiplier);
    float i;
    for (i = 0; i < (int)(P(current_player_index).ammo * multiplier); ++i)
        quad(320 + i * spacing * 10, y, spacing * 16, h);
    tint(1, 1, 1, .3f);
    for (i = (float)(int)(P(current_player_index).ammo * multiplier);
         i < (int)(P(current_player_index).clip_size * multiplier); ++i)
        quad(320 + i * spacing * 10, y, spacing * 16, h);
}
__forceinline void health_bar(const float &hp, float y) {
    tint(.38f, .04f, .04f, .9f);
    float fraction = hp * .01f;
    if (fraction > 1) {
        float red = fraction * .38f, alpha = fraction * .9f;
        tint(red > 1 ? 1 : red, .04f, .04f, alpha > 1 ? 1 : alpha);
        fraction = 1;
    }
    if (fraction > 0)
        quad(12, y, 12 + fraction * 124, 11);
}
__forceinline void reload_bar(int player, float y) {
    float fraction = P(player).reload / P(player).reload_duration;
    if (fraction > 1)
        fraction = 1;
    if (fraction > 0)
        quad(322, y, 12 + fraction * 294, 2);
}
__forceinline int shown_xp() {
    float &timer = UI_FIELD(freeware_hud_xp_timer, hud_xp_timer);
    int &shown = P(current_player_index).displayed_experience;
    int xp = UI_FIELD(P(current_player_index).experience, run.experience);
    timer -= frame_dt;
    if (timer <= 0) {
        timer += .1f;
        if (shown < xp)
            shown += (xp - shown) / 2 + 1;
    }
    if (shown > xp)
        shown = xp;
    return shown;
}
} // namespace
extern "C" void gameplay_render_hud() {
#ifdef CRIMSON_FREEWARE_CLIENT
    char buffer[80];
#else
    char *buffer = freeware_ui_buffer;
#endif
    filter(1);
    tint(.7f, .7f, .7f, 1);
    bind(texture("bar"));
    begin();
    uv(0, 0, 1, 1);
    angle(0);
    if (config_player_count == 1)
        quad(0, 0, 640, 64);
    end();
    if (config_game_mode == 1 || config_game_mode == 3) {
        scale(1);
#ifdef CRIMSON_FREEWARE_CLIENT
        bind("bullet_i");
#else
        bind(freeware_bullet_icon);
#endif
        begin();
        angle(0);
        for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
            if (HEALTH(current_player_index) <= 0)
                continue;
            tint(1, 1, 1, .7f);
            float y = config_player_count == 1 ? 16.f : current_player_index == 0 ? 10.f : 30.f;
            float h = config_player_count == 1 ? 22.f : 18.f;
            if (UI_FIELD(P(0).perks[perk_id_ammo_maniac], run.perks[perk_id_ammo_maniac]) > 0)
                rounds(1.2f, y, h);
            else
                rounds(1.f, y, h);
        }
        end();
    }
    current_player_index = 0;
    filter(2);
    angle(0);
    bind(texture("bullet"));
    uv(0, 0, 1, 1);
    tint(.4f, .4f, .4f, .8f);
    begin();
    if (config_player_count == 1) {
        quad(10, 35, 140, 15);
        health_bar(HEALTH(0), 37);
        if (config_game_mode != 2) {
            tint(.4f, .4f, .4f, .8f);
            quad(320, 5, 310, 6);
            tint(.04f, .04f, .38f, .9f);
            reload_bar(0, 7);
        }
    } else {
        quad(10, 15, 140, 15);
        quad(10, 35, 140, 15);
        health_bar(HEALTH(0), 17);
        health_bar(HEALTH(1), 37);
        if (config_game_mode != 2) {
            tint(.4f, .4f, .4f, .8f);
            quad(320, 2, 310, 6);
            quad(320, 50, 310, 6);
            tint(.04f, .04f, .38f, .9f);
            reload_bar(0, 4);
            reload_bar(1, 52);
        }
    }
    end();
    tint(1, 1, 1, 1);
    if (config_player_count == 1 && config_game_mode == 1) {
        filter(1);
        tint(1, 1, 1, 1);
        bind(texture("ui_text"));
        angle(0);
        begin();
        freeware_hud_set_row(2);
        quad(-3, -6, 256, 50);
        end();
        filter(2);
        tint(1, 1, 1, .7f);
        scale(.7f);
        sprintf(buffer, "%d", shown_xp());
        tint(0, 0, 0, 1);
        text(220, 7, buffer);
        tint(.8f, .1f, .1f, 1);
        text(220, 7, buffer);
    } else if (config_player_count == 1 && config_game_mode == 3) {
        tint(1, 1, 1, .7f);
        scale(.625f);
        sprintf(buffer, "xp: %d", shown_xp());
        tint(1, 1, 1, .7f);
        text(10, 4, buffer);
    } else if (config_game_mode == 2) {
        scale(.7f);
        tint(1, 1, 1, 1);
        sprintf(buffer, "Seconds survived: %d", (int)UI_FIELD(freeware_elapsed_seconds, run.seconds));
        if (config_player_count == 1)
            text(3, 7, buffer);
        else
            text(260, 15, buffer);
    }
    if (UI_FIELD(game_state_id, frame_state()) == 3 && UI_FIELD(freeware_game_active, active_run))
        UI_FIELD(freeware_elapsed_seconds, run.seconds) += frame_dt;
#ifdef CRIMSON_FREEWARE_CLIENT
    freeware_elapsed_seconds = UI_GAME.run.seconds;
#endif
    tint(1, 1, 1, 1);
    uv(0, 0, 1, 1);
    filter(2);
    for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
        if (HEALTH(current_player_index) > 0) {
            scale(.57f);
            if (config_player_count == 1) {
                scale(.67f);
                text(12, 55, weapon_name_get(P(current_player_index).weapon));
            } else
                text(150, current_player_index ? 32.f : 12.f, weapon_name_get(P(current_player_index).weapon));
        }
    }
    current_player_index = 0;
    if (UI_FIELD(freeware_pending_perks, run.pending) > 0 && config_game_mode != 2) {
        tint(.9f, .8f, .1f, .7f);
        scale(.6f);
        filter(1);
        tint(1, 1, 1, 1);
        bind(texture("ui_text"));
        angle(0);
        begin();
        freeware_hud_set_row(0);
        quad(viewport_width() - 240.f, viewport_height() - 50.f, 256, 50);
        end();
        filter(2);
    }
}
