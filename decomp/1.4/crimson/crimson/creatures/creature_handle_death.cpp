#include "freeware_edition.h"
// crimson.exe 0x405e10. Attribution follows the current player global even for a projectile fired earlier.
#include "crimsonland_types.h"
#include <math.h>
#ifdef CRIMSON_FREEWARE_CLIENT
// The client wrapper also publishes XP, pickup and first-kill changes to its Run.
#define creature_handle_death freeware_creature_handle_death_body
#endif
#include "../effects/freeware_ice_mark.h"
extern "C" {
extern creature_t creature_pool[512];
#if CL_BUILD == 10300
extern freeware_player_t player_state_table[2];
#define PLAYER player_state_table[current_player_index]
#else
extern player_state_t player_state_table[2];
#define PLAYER player_state_table[current_player_index].freeware
#endif
extern sprite_effect_t sprite_effect_pool[384];
extern int current_player_index, creature_spawned_count, perk_id_bloody_mess;
extern int freeware_first_kill_xp, freeware_pickup_id, freeware_no_pickup;
extern unsigned char freeware_player_moved;
extern vec2f_t freeware_first_kill_position;
extern float frame_dt, bonus_freeze_timer;
extern game_mode_id_t config_game_mode;
void bonus_spawn_at(const vec2f_t *);
int fx_spawn_sprite(const vec2f_t *, const vec2f_t *, float);
int crt_rand();
}
static __forceinline float distance_between(const vec2f_t &a, const vec2f_t &b) {
    float dx = a.x - b.x, dy = a.y - b.y;
    return (float)sqrt(dx * dx + dy * dy);
}
#if CL_BUILD == 10300
extern "C" void creature_handle_death(int slot, int) {
#else
extern "C" void creature_handle_death(int slot, int, unsigned char leave_corpse) {
#endif
#if FREEWARE_EDITION == 10300
    creature_pool[slot].death_timer -= frame_dt;
#else
    if (!creature_pool[slot].active)
        return;
    if (!PLAYER.experience && !freeware_player_moved) {
        freeware_first_kill_position = creature_pool[slot].position;
        freeware_first_kill_xp = (int)creature_pool[slot].freeware.reward;
    }
    if (leave_corpse) {
        if (FREEWARE_EDITION != 10002)
            creature_pool[slot].death_timer -= frame_dt;
    } else {
        creature_pool[slot].active = 0;
    }
#endif
    if (PLAYER.perks[perk_id_bloody_mess] > 0) {
#if FREEWARE_EDITION == 10300
        PLAYER.experience += (int)(creature_pool[slot].freeware.reward * 1.5);
#else
        PLAYER.experience -= (int)(creature_pool[slot].freeware.reward * -1.5);
#endif
    } else {
        PLAYER.experience = (int)(PLAYER.experience + creature_pool[slot].freeware.reward);
    }
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10002
    // The 1.0.2 projectile death branch places the pickup directly on the kill (0x40314d).
    if (freeware_pickup_id == freeware_no_pickup && config_game_mode != 2 &&
        (crt_rand() % 15 == 1 || (PLAYER.weapon == 1 && crt_rand() % 3 == 1)))
        bonus_spawn_at(&creature_pool[slot].position);
#else
    if (freeware_pickup_id == freeware_no_pickup && config_game_mode != 2 &&
        (crt_rand() % 8 == 1 || (PLAYER.weapon == 1 && crt_rand() % 3 == 1))) {
        if (distance_between(creature_pool[slot].position, PLAYER.position) > 64.0f)
            bonus_spawn_at(&creature_pool[slot].position);
    }
#endif
    --creature_spawned_count;
    if (FREEWARE_EDITION != 10002 && bonus_freeze_timer != 0) {
        vec2f_t mark;
        const vec2f_t &origin = creature_pool[slot].position;
        for (int i = 0; i < 30; ++i) {
            float size = (float)(crt_rand() % 10 + 5);
            float heading = (crt_rand() % 628) * .01f;
            float radius = (crt_rand() % 55) * (i * .04f);
            vec2f_t offset = {(float)cos(heading) * radius, (float)sin(heading) * radius};
            mark.x = offset.x + origin.x;
            mark.y = offset.y + origin.y;
            freeware_shard(&mark, size);
        }
        // The sprite takes a zero velocity in the vector used for the shard marks.
        mark.x = 0;
        mark.y = 0;
        int idx = fx_spawn_sprite(&origin, &mark, 12);
        creature_pool[slot].active = 0;
        sprite_effect_pool[idx].color_r *= .56f;
        sprite_effect_pool[idx].color_g *= .7f;
        sprite_effect_pool[idx].color_b *= .9f;
    }
}
#undef PLAYER
