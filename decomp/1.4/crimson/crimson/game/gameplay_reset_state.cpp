#include "freeware_level.h"

extern "C" {
extern float freeware_revive_timer, freeware_fps_min, freeware_fps_max;
extern float bonus_reflex_boost_timer, bonus_fire_bullets_timer, bonus_freeze_timer;
extern float freeware_jinx_timer, freeware_bomb_age, freeware_next_spawn, freeware_pickup_time;
extern int freeware_first_kill_xp, plaguebearer_infection_count, freeware_pending_perks;
extern int freeware_kills, highscore_record_hits, highscore_record_shots_fired;
extern int freeware_encounter_id, freeware_encounter_page, freeware_encounter_day;
extern unsigned char freeware_encounter_active, freeware_music_started, freeware_player_moved;
extern unsigned char freeware_spawn_enabled;
extern vec2f_t freeware_first_kill_position;
extern int config_player_count, creature_spawned_count, freeware_corpse_count, freeware_blood_count;
extern int freeware_no_pickup, freeware_pickup_id;
extern game_mode_id_t config_game_mode;
extern projectile_pool_t projectile_pool;
extern secondary_projectile_pool_t secondary_projectile_pool;
extern sprite_effect_t sprite_effect_pool[];
extern creature_t creature_pool[];
void projectile_reset_pools();
void player_reset_all();
void terrain_generate(unsigned char textured);
}

extern "C" void gameplay_reset_state()
{
#if CL_BUILD >= 10400
    freeware_revive_timer = 0;
    freeware_first_kill_xp = 0;
    vec2f_t start = {-100.0f, 0.0f};
    freeware_first_kill_position = start;
    freeware_player_moved = 0;
#endif
#if CL_BUILD >= 10300
    plaguebearer_infection_count = 0;
    bonus_reflex_boost_timer = 0;
    freeware_fps_min = 10000.0f;
    freeware_fps_max = 0;
    freeware_kills = 0;
    highscore_record_hits = 0;
    highscore_record_shots_fired = 0;
    freeware_pending_perks = 0;
#endif
    bonus_fire_bullets_timer = 0;
    bonus_freeze_timer = 0;
#if CL_BUILD >= 10300
    freeware_jinx_timer = 0;
    freeware_bomb_age = -1.0f;
#endif
    projectile_reset_pools();
#if CL_BUILD < 10300
    freeware_encounter_id = 1;
    freeware_encounter_active = 0;
#else
    freeware_encounter_active = 0;
    freeware_encounter_id = 1;
#endif
    freeware_encounter_page = 1;
    freeware_encounter_day = 1;
#if CL_BUILD < 10300
    freeware_spawn_enabled = 0;
    freeware_pending_perks = 0;
#endif
    freeware_music_started = 0;
    freeware_next_spawn = 0;
    player_reset_all();

    int i;
    for (i = 0; i < PROJECTILE_POOL_CAPACITY; ++i)
        projectile_pool[i].active = 0;
#if CL_BUILD < 10300
    for (i = 0; i < 128; ++i)
        creature_pool[i].active = 0;
#else
#if CL_BUILD >= 10400
    const int sprite_count = 384;
#else
    const int sprite_count = 256;
#endif
    for (i = 0; i < sprite_count; ++i)
        sprite_effect_pool[i].active = 0;
    for (i = 0; i < 64; ++i)
        secondary_projectile_pool[i].active = 0;
    for (i = 0; i < 512; ++i) {
        creature_pool[i].active = 0;
        creature_pool[i].freeware.player = i % config_player_count;
#if CL_BUILD >= 10400
        if (config_game_mode == 3)
            creature_pool[i].ai_mode = 0;
        else
            creature_pool[i].ai_mode = 1;
#endif
    }

    freeware_pickup_id = freeware_no_pickup;
    freeware_pickup_time = 1;
#endif
    creature_spawned_count = 0;
    freeware_corpse_count = 0;
    freeware_blood_count = 0;
#if CL_BUILD >= 10300
    if (config_game_mode >= 3)
        terrain_generate(!freeware_current_map->flag);
    else
#endif
        terrain_generate(1);
}
