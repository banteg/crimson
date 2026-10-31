// The 0x408600 level-up roll precedes the separate picker at 0x408cf0.
#include "cl_build.h"
#if CL_BUILD == 10400
#include "crimsonland_types.h"
#include <math.h>
#include <string.h>
extern "C" {
extern game_mode_id_t config_game_mode;
extern player_state_t player_state_table[2];
extern creature_t creature_pool[512];
extern unsigned char perk_choice_flags[48], freeware_spawn_enabled;
extern int current_player_index, creature_spawned_count, perk_id_count, freeware_pending_perks;
int crt_rand();
int creature_alloc_slot();
int sfx_play_panned(int, float, float);
}
static void spawn_boss(int level) {
    struct Boss {
        int level, type;
        float size, health, damage, speed;
        double xp;
        effect_color_t tint;
    };
    static const Boss bosses[] = {{3, 1, 92, 1200, 10, 1.2f, 2000, {28 / 255.f, 131 / 255.f, 174 / 255.f, 1}},
                                  {5, 2, 98, 1400, 10, 1.2f, 3000, {192 / 255.f, 0, 192 / 255.f, 1}},
                                  {8, 1, 128, 3000, 10, 1.2f, 5000, {192 / 255.f, 0, 0, 1}},
                                  {13, 1, 128, 10000, 30, 2.6f, 4000, {.7f, .7f, .7f, .4f}},
                                  {17, 1, 100, 10000, 30, 2.8f, 5000, {1, 1, 1, 1}}};
    for (int i = 0; i < 5; ++i)
        if (level == bosses[i].level) {
            const Boss &b = bosses[i];
            creature_t &c = creature_pool[creature_alloc_slot()];
            c.active = 1;
            c.pos_x = c.pos_y = -20;
            c.vel_x = c.vel_y = 0;
            c.death_timer = 16;
            c.health = b.health;

            if (level == 8 || level == 17)
                c.hit_flash_timer = -.5f;
            c.freeware.type = b.type;
            c.freeware.heading = crt_rand() % 314 * .01f;
            c.freeware.size = b.size;
            c.freeware.contact_damage = b.damage;
            c.freeware.move_speed = b.speed;
            c.freeware.color = b.tint;
            c.freeware.reward = b.xp;
            c.freeware.attack_cooldown = 0;
            c.freeware.force_target = 0;
            ++creature_spawned_count;
        }
}

extern "C" void player_check_level() {
    int saved = current_player_index;
    current_player_index = 0;
    if (config_game_mode == 2)
        return;
    freeware_player_t &p = player_state_table[0].freeware;
    if (p.experience > 1000 * pow(p.level + 1., 1.75)) {
        ++p.level;
        if (freeware_spawn_enabled)
            spawn_boss(p.level);
        memset(perk_choice_flags, 0, 48);
        for (int i = 0; i < 5; ++i) {
            int slot;
            do {
                slot = crt_rand() % (perk_id_count + 1);
            } while (perk_choice_flags[slot]);
            perk_choice_flags[slot] = 1;
        }
        ++freeware_pending_perks;
        sfx_play_panned(17, .45f, .5f);
    }
    current_player_index = saved;
}
#endif
