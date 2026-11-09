#include "freeware_level.h"
#include <stdio.h>
extern "C" {
extern unsigned char freeware_spawn_enabled;
extern int freeware_level_number, freeware_pickup_id, freeware_no_pickup, current_player_index;
extern float freeware_elapsed_seconds, freeware_pickup_time, freeware_berserk_timer;
extern projectile_pool_t projectile_pool;
extern sprite_effect_t sprite_effect_pool[];
extern secondary_projectile_pool_t secondary_projectile_pool;
extern creature_t creature_pool[];
extern freeware_player_t player_state_table[];
extern vec2f_t freeware_aim_screen;
extern char freeware_ui_buffer[];
void creature_reset_all();
void terrain_generate(unsigned char textured);
}
static __forceinline freeware_player_t &current_player() {
    return player_state_table[current_player_index];
}

extern "C" void level_load_next() {
    creature_reset_all();
    ++freeware_level_number;
    freeware_spawn_enabled = 0;
    sprintf(freeware_ui_buffer, "levels\\level_%d.lvl", freeware_level_number);
    if (!freeware_current_map->load(freeware_ui_buffer)) {
        freeware_level_number = 1;
        sprintf(freeware_ui_buffer, "levels\\level_%d.lvl", freeware_level_number);
        freeware_current_map->load(freeware_ui_buffer);
    }
    terrain_generate(!freeware_current_map->flag);
    int i;
    for (i = 0; i < 64; ++i)
        projectile_pool[i].active = 0;
    for (i = 0; i < (CL_BUILD == 10300 ? 256 : 384); ++i)
        sprite_effect_pool[i].active = 0;
    for (i = 0; i < 64; ++i)
        secondary_projectile_pool[i].active = 0;
    freeware_pickup_id = freeware_no_pickup;
    freeware_elapsed_seconds = 0;
    freeware_pickup_time = 0;
    freeware_level_map *map = freeware_current_map;
    int previous = current_player_index;
    current_player_index = 0;
    freeware_berserk_timer = 0;
    for (; current_player_index < 2; ++current_player_index) {
        current_player().shield = 0;
        current_player().control_reserved = 0;
        current_player().plaguebearer = 0;
        current_player().position = map->start;
        if (current_player_index == 1) {
            vec2f_t &second = player_state_table[1].position;
            vec2f_t offset = {80, 0};
            second.x += offset.x;
            second.y += offset.y;
        }
        current_player().size = 48;
        current_player().speed_multiplier = 2;
        current_player().heading = map->start_heading;
        current_player().spread = 1;
        current_player().move_speed = 0;
        current_player().ammo = 10;
        current_player().clip_size = 10;
        current_player().reload_duration = 1;
        current_player().reload = 0;
        current_player().cooldown = .8f;
        current_player().weapon = 1;
        vec2f_t cursor = {320, 140};
        freeware_aim_screen = cursor;
    }
    current_player_index = previous;
    for (i = 0; i < 512; ++i)
        creature_pool[i].plague_infected = 0;
    map->arm_triggers();
    current_player_index = 0;
}
