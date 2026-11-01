// 0x408440. The run reset initializes both records and preserves aim, walk
// phase and the binding bytes from the preceding run.
#include "freeware_level.h"
#include <string.h>
extern "C" {
extern player_state_t player_state_table[2];
extern creature_t creature_pool[512];
extern game_mode_id_t config_game_mode;
extern int freeware_arena_width, freeware_arena_height, freeware_pickup_id, freeware_no_pickup;
extern float freeware_elapsed_seconds, freeware_pickup_time, freeware_berserk_timer;
extern vec2f_t freeware_aim_screen;
void player_reset_all() {
    freeware_level_map *map = freeware_current_map;
    freeware_elapsed_seconds = 0;
    freeware_pickup_time = 0;
    freeware_pickup_id = freeware_no_pickup;
    freeware_berserk_timer = 0;
    for (int i = 0; i < 2; ++i) {
        freeware_player_t &p = player_state_table[i].freeware;
        p.shield = 0;
        p.control_reserved = 0;
        p.plaguebearer = 0;
        if (config_game_mode == 3)
            p.position = map->start;
        else {
            p.position.x = freeware_arena_width * .5f;
            p.position.y = freeware_arena_height * .5f;
        }
        p.health = 100;
        if (i == 1)
            player_state_table[1].freeware.position.x += 80;
        p.size = 48;
        p.speed_multiplier = 2;
        p.level = 1;
        p.heading = map->start_heading;
        p.experience = 0;
        p.displayed_experience = 0;
        p.spread = 1;
        p.move_speed = 0;
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10002
        p.ammo = p.clip_size = 30;
#else
        p.ammo = 10;
        p.clip_size = 10;
#endif
        p.reload_duration = 1;
        p.reload = 0;
        freeware_aim_screen.x = 320;
        p.cooldown = .8f;
        p.weapon = 1;
        p.previous_weapon = 0;
        freeware_aim_screen.y = 140;
        memset(p.perks, 0, sizeof(p.perks));
        for (int j = 0; j < 512; ++j)
            creature_pool[j].plague_infected = 0;
    }
}
}
