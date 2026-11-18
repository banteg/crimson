// The milestone spawns and five perk draws precede the perk selection screen.
#include "freeware_edition.h"
#include "crimsonland_types.h"
#include <math.h>
#include <string.h>

#ifdef CRIMSON_FREEWARE_CLIENT
#include "game.h"
extern freeware::Game *freeware_frame_game;
#endif

extern "C" {
extern game_mode_id_t config_game_mode;
#if CL_BUILD < 10400
extern freeware_player_t player_state_table[2];
#define PLAYER player_state_table[current_player_index]
#else
extern player_state_t player_state_table[2];
#define PLAYER player_state_table[current_player_index].freeware
#endif
extern creature_t creature_pool[CL_BUILD == 10002 ? 128 : 512];
extern unsigned char perk_choice_flags[], freeware_spawn_enabled;
#ifndef CRIMSON_FREEWARE_CLIENT
extern unsigned char freeware_level_up_reset_byte;
extern int freeware_perk_hover;
#endif
extern int current_player_index, creature_spawned_count, perk_id_count, freeware_pending_perks;
int crt_rand();
int creature_alloc_slot();
int sfx_play_panned(int, float, float);
}

static __forceinline void spawn_boss(int level, int species, float health, float speed, float size,
                                     double xp, float red, float green, float blue, float alpha) {
    int id = creature_alloc_slot();
    creature_pool[id].freeware.type = species;
    creature_pool[id].active = 1;
    creature_pool[id].freeware.force_target = 0;
    if (level == 13 || level == 17)
        creature_pool[id].freeware.contact_damage = 30;
    creature_pool[id].death_timer = 16;
    vec2f_t position = {-20, -20};
    creature_pool[id].position = position;
    vec2f_t velocity = {0, 0};
    creature_pool[id].velocity = velocity;
    if (level == 3)
        creature_pool[id].freeware.contact_damage = 10;
    creature_pool[id].freeware.heading = (crt_rand() % 314) * .01f;
    creature_pool[id].freeware.attack_cooldown = 0;
    if (level == 5)
        creature_pool[id].freeware.contact_damage = 10;
    creature_pool[id].freeware.move_speed = speed;
    creature_pool[id].freeware.size = size;
    if (level == 8)
        creature_pool[id].freeware.contact_damage = 10;
    creature_pool[id].health = health;
    effect_color_t tint = {red, green, blue, alpha};
    creature_pool[id].freeware.color = tint;
    creature_pool[id].freeware.reward = xp;
#if FREEWARE_EDITION != 10002
    if (level == 8 || level == 17)
        creature_pool[id].hit_flash_timer = -.5f;
#endif
    ++creature_spawned_count;
}

extern "C" void player_check_level() {
#if FREEWARE_EDITION != 10002
    int saved = current_player_index;
    current_player_index = 0;
#endif
    if (config_game_mode == 2)
        return;
    const double exponent = FREEWARE_EDITION == 10002 ? (double)1.7f : 1.75;
    if (PLAYER.experience > 1000.0f * (float)pow(PLAYER.level + 1.0f, exponent)) {
        ++PLAYER.level;
        if (freeware_spawn_enabled) {
            if (PLAYER.level == 3)
                spawn_boss(3, 1, FREEWARE_EDITION == 10002 ? 2000 : 1200, 1.2f, 92, 2000,
                           28 / 255.f, 131 / 255.f, 174 / 255.f, 1);
            if (PLAYER.level == 5)
                spawn_boss(5, 2, FREEWARE_EDITION == 10002 ? 2000 : 1400, 1.2f, 98, 3000,
                           192 / 255.f, 0, 192 / 255.f, 1);
            if (PLAYER.level == 8)
                spawn_boss(8, 1, FREEWARE_EDITION == 10002 ? 5000 : 3000, 1.2f, 128, 5000,
                           192 / 255.f, 0, 0, 1);
            if (PLAYER.level == 13)
                spawn_boss(13, 1, FREEWARE_EDITION == 10002 ? 15000 : 10000, 2.6f, 128,
                           FREEWARE_EDITION == 10002 ? 500000 : 4000, .7f, .7f, .7f, .4f);
#if FREEWARE_EDITION != 10002
            if (PLAYER.level == 17)
                spawn_boss(17, 1, 10000, 2.8f, 100, 5000, 1, 1, 1, 1);
#endif
        }
#ifdef CRIMSON_FREEWARE_CLIENT
        freeware_frame_game->perk_hover = 0;
#else
        freeware_perk_hover = 0;
#endif
        memset(perk_choice_flags, 0, FREEWARE_EDITION < 10400 ? 32 : 48);
#ifndef CRIMSON_FREEWARE_CLIENT
        // This byte is only written by the native level-up routine.
        freeware_level_up_reset_byte = 0;
#endif
        for (int i = 0; i < 5; ++i) {
            int slot;
            do {
                const int choices = perk_id_count + 1;
                slot = crt_rand() % choices;
            } while (perk_choice_flags[slot]);
            perk_choice_flags[slot] = 1;
        }
        ++freeware_pending_perks;
        sfx_play_panned(17, .45f, .5f);
    }
#if FREEWARE_EDITION != 10002
    current_player_index = saved;
#endif
}

#undef PLAYER
