// Crimsonland 1.3.0 (0x411860) and 1.4.0 (0x416a00).
#include "freeware_edition.h"
#if FREEWARE_EDITION == 10002
#include "gameplay_hud_102.h"
extern "C" void gameplay_render_hud() { hud102::render(); }
#else
#include "freeware_ui.h"
#include <stdio.h>
using namespace ui140;
extern "C" {
extern int perk_id_ammo_maniac;
extern float freeware_hud_xp_timer;
void freeware_hud_set_row(int);
}
namespace {
#define HUD_PLAYER UI_PLAYER(current_player_index)
#define HUD_XP UI_FIELD(HUD_PLAYER.experience, run.experience)
#define HEALTH(i) UI_FIELD(UI_PLAYER(i).health, actor(i).health)
__forceinline void rounds(float multiplier, float y, float height, float &spacing, float &round) {
    if (HUD_PLAYER.clip_size * multiplier > 30)
        spacing = multiplier == 1.f ? 30.f / HUD_PLAYER.clip_size
                                    : 30.f / (HUD_PLAYER.clip_size * multiplier);
    for (round = 0; round < (int)(HUD_PLAYER.ammo * multiplier); ++round)
        quad(320 + round * spacing * 10, y, spacing * 16, height);
    tint(1, 1, 1, .3f);
    for (round = (float)(int)(HUD_PLAYER.ammo * multiplier);
         round < (int)(HUD_PLAYER.clip_size * multiplier); ++round)
        quad(320 + round * spacing * 10, y, spacing * 16, height);
}
__forceinline void health_bar(const float &hp, float y) {
    tint(.38f, .04f, .04f, .9f);
    float fraction = hp * .01f;
    if (fraction > 1) {
        float red = fraction * .38f, alpha = fraction * .9f;
        if (red > 1)
            red = 1;
        if (alpha > 1)
            alpha = 1;
        tint(red, .04f, .04f, alpha);
        fraction = 1;
    }
    if (fraction > 0)
        quad(12, y, 12 + fraction * 124, 11);
}
__forceinline void reload_bar(int player, float y) {
    float fraction = UI_PLAYER(player).reload / UI_PLAYER(player).reload_duration;
    if (fraction > 1)
        fraction = 1;
    if (fraction > 0)
        quad(322, y, 12 + fraction * 294, 2);
}
__forceinline int shown_xp() {
    float &timer = UI_FIELD(freeware_hud_xp_timer, hud_xp_timer);
    timer -= frame_dt;
    if (timer <= 0) {
        timer += .1f;
        if (HUD_PLAYER.displayed_experience < HUD_XP)
            HUD_PLAYER.displayed_experience += (HUD_XP - HUD_PLAYER.displayed_experience) / 2 + 1;
    }
    if (HUD_PLAYER.displayed_experience > HUD_XP)
        HUD_PLAYER.displayed_experience = HUD_XP;
    return HUD_PLAYER.displayed_experience;
}
__forceinline void draw_survival_time(char *buffer, float x, float y) {
    scale(.7f);
    tint(1, 1, 1, 1);
    sprintf(buffer, "Seconds survived: %d", (int)UI_FIELD(freeware_elapsed_seconds, run.seconds));
    text(x, y, buffer);
}
} // namespace
extern "C" void gameplay_render_hud() {
#ifdef CRIMSON_FREEWARE_CLIENT
    char buffer[80];
#else
    char *buffer = freeware_ui_buffer;
#endif
    vec2f_t position;
    float height;
    filter(1);
    tint(.7f, .7f, .7f, 1);
    bind("bar");
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

            if (config_player_count == 1) {
                position.y = 16;
                height = 22;
            } else {
                if (config_player_count == 2 && current_player_index == 0)
                    position.y = 10;
                else
                    position.y = 30;
                height = 18;
            }
            float round, spacing = 1;
            if (UI_FIELD(UI_PLAYER(0).perks[perk_id_ammo_maniac], run.perks[perk_id_ammo_maniac]) > 0)
                rounds(1.2f, position.y, height, spacing, round);
            else
                rounds(1.f, position.y, height, spacing, round);
        }
        end();
    }
    current_player_index = 0;
    filter(2);
    angle(0);
    bind("bullet");
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
    if (config_player_count == 1) {
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
            sprintf(buffer, "%d", shown_xp());
            tint(0, 0, 0, 1);
            text(220, 7, buffer);
            tint(.8f, .1f, .1f, 1);
            text(220, 7, buffer);
        } else if (config_game_mode == 3) {
            tint(1, 1, 1, .7f);
            scale(.625f);
            sprintf(buffer, "xp: %d", shown_xp());
            tint(1, 1, 1, .7f);
            text(10, 4, buffer);
        } else if (config_game_mode == 2) {
            draw_survival_time(buffer, 3, 7);
        }
    }
    if (config_game_mode == 2 && config_player_count == 2) {
        draw_survival_time(buffer, 260, 15);
    }
    if ((FREEWARE_EDITION != 10002 || config_game_mode == 2) && UI_FIELD(game_state_id, frame_state()) == 3 &&
        UI_FIELD(freeware_game_active, active_run)) {
        float elapsed = UI_FIELD(freeware_elapsed_seconds, run.seconds);
        elapsed += frame_dt;
        UI_FIELD(freeware_elapsed_seconds, run.seconds) = elapsed;
    }
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
                position.x = 12;
                position.y = 55;
            } else {
                position.x = 150;
                position.y = 12;
                if (current_player_index)
                    position.y = 32;
            }
#ifdef CRIMSON_FREEWARE_CLIENT
            text(position.x, position.y, weapon_name_get(HUD_PLAYER.weapon));
#else
            grim_interface_ptr->grim_draw_text_mono(position.x, position.y,
                                                    weapon_name_get(HUD_PLAYER.weapon));
#endif
        }
    }
    current_player_index = 0;
    if (UI_FIELD(freeware_pending_perks, run.pending) >= 1 && config_game_mode != 2) {
        tint(.9f, .8f, .1f, .7f);
        scale(.6f);
        filter(1);
        tint(1, 1, 1, 1);
        bind("ui_text");
        angle(0);
        begin();
        freeware_hud_set_row(0);
        quad(viewport_width() - 240.f, viewport_height() - 50.f, 256, 50);
        end();
        filter(2);
    }
}
#endif
