// crimson.exe 0x405e10. Attribution follows the current player global even for a projectile fired earlier.
#include "crimsonland_types.h"
#include <math.h>
#ifdef CRIMSON_FREEWARE_CLIENT
// The client wrapper also publishes XP, pickup and first-kill changes to its Run.
#define creature_handle_death freeware_creature_handle_death_body
#endif
extern "C" {
extern creature_t creature_pool[512];
extern player_state_t player_state_table[2];
extern sprite_effect_t sprite_effect_pool[384];
extern int current_player_index, creature_spawned_count, perk_id_bloody_mess;
extern int freeware_first_kill_xp, freeware_pickup_id, freeware_no_pickup;
extern unsigned char freeware_player_moved;
extern vec2f_t freeware_first_kill_position;
extern float frame_dt, bonus_freeze_timer;
extern game_mode_id_t config_game_mode;
void bonus_spawn_at(const vec2f_t *);
void freeware_shard(const vec2f_t *, float, float);
int fx_spawn_sprite(const vec2f_t *, const vec2f_t *, float);
int crt_rand();
}
extern "C" void creature_handle_death(int slot, int, unsigned char leave_corpse) {
    creature_t &c = creature_pool[slot];
    if (!c.active)
        return;
    freeware_player_t &p = player_state_table[current_player_index].freeware;
    if (!p.experience && !freeware_player_moved) {
        freeware_first_kill_position = c.position;
        freeware_first_kill_xp = (int)c.freeware.reward;
    }
    if (leave_corpse)
        c.death_timer -= frame_dt;
    else
        c.active = 0;
    if (p.perks[perk_id_bloody_mess] > 0)
        p.experience -= (int)(c.freeware.reward * -1.5);
    else
        p.experience = (int)(p.experience + c.freeware.reward);
    if (freeware_pickup_id == freeware_no_pickup && config_game_mode != 2 &&
        (crt_rand() % 8 == 1 || (p.weapon == 1 && crt_rand() % 3 == 1))) {
        float x = c.pos_x - p.position.x, y = c.pos_y - p.position.y;
        if (sqrt((double)x * x + (double)y * y) > 64)
            bonus_spawn_at(&c.position);
    }
    --creature_spawned_count;
    if (bonus_freeze_timer != 0) {
        for (int i = 0; i < 30; ++i) {
            float size = (float)(crt_rand() % 10 + 5);
            float heading = (crt_rand() % 628) * .01f;
            int radius = crt_rand() % 55;
            vec2f_t mark = {(float)(c.pos_x + cos(heading) * i * .04f * radius),
                            (float)(c.pos_y + sin(heading) * i * .04f * radius)};
            freeware_shard(&mark, size, (crt_rand() % 612) * .01f);
        }
        vec2f_t zero = {0, 0};
        int idx = fx_spawn_sprite(&c.position, &zero, 12);
        c.active = 0;
        sprite_effect_pool[idx].color_r *= .56f;
        sprite_effect_pool[idx].color_g *= .7f;
        sprite_effect_pool[idx].color_b *= .9f;
    }
}
