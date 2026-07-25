#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" void bonus_try_spawn_on_kill(const vec2f_t *pos)
{
    bonus_entry_t *entry;

    if (config_game_mode == GAME_MODE_TYPO_SHOOTER
        || demo_mode_active
        || config_game_mode == GAME_MODE_RUSH
        || config_game_mode == GAME_MODE_TUTORIAL) {
        return;
    }

    if ((player_state_table[0].weapon_id == 1
         || (player_state_table[1].weapon_id == 1 && config_blob.player_count == 2))
        && (crt_rand() & 3) <= 2) {
        int duplicate_count;
        bonus_entry_t *scan;

        entry = bonus_spawn_at_pos(pos);
        entry->bonus_id = BONUS_ID_WEAPON;
        entry->time.amount = weapon_pick_random_available();
        if (entry->time.amount == 1) {
            entry->time.amount = weapon_pick_random_available();
        }

        duplicate_count = 0;
        if (entry->bonus_id != BONUS_ID_POINTS) {
            scan = &bonus_pool[0];
            do {
                if (scan->bonus_id == entry->bonus_id) {
                    ++duplicate_count;
                }
                ++scan;
            } while ((int)scan < (int)&bonus_pool[16]);
        }
        if (duplicate_count >= 2
            || entry->time.amount == 1
            || perk_count_get(perk_id_my_favourite_weapon) != 0) {
            entry->bonus_id = BONUS_ID_NONE;
            return;
        }
    } else {
        int duplicate_count;
        int roll = crt_rand();
        bonus_entry_t *scan;

        if (roll % 9 != 1 && (player_state_table[0].weapon_id != 1 || crt_rand() % 5 != 1)) {
            if (perk_count_get(perk_id_bonus_magnet) == 0) {
                return;
            }
            if (crt_rand() % 10 != 2) {
                return;
            }
        }

        entry = bonus_spawn_at_pos(pos);
        if (entry->bonus_id == BONUS_ID_WEAPON) {
            float dx = pos->x - player_state_table[0].position.x;
            float dy = pos->y - player_state_table[0].position.y;
            float distance_sq = dx * dx;
            distance_sq += dy * dy;
            if ((float)sqrt(distance_sq) < 56.0f) {
                entry->bonus_id = BONUS_ID_POINTS;
                entry->time.amount = 100;
            }
        }

        duplicate_count = 0;
        if (entry->bonus_id != BONUS_ID_POINTS) {
            scan = &bonus_pool[0];
            do {
                if (scan->bonus_id == entry->bonus_id) {
                    ++duplicate_count;
                }
                ++scan;
            } while ((int)scan < (int)&bonus_pool[16]);
        }
        bool reject = false;
        if (duplicate_count >= 2) {
            reject = true;
        } else if (
            entry->time.amount == player_state_table[0].weapon_id) {
            reject = true;
        }
        if (reject) {
            entry->bonus_id = BONUS_ID_NONE;
            return;
        }
    }

    if (entry != 0 && entry != &bonus_pool_sentinel) {
        int count;
        effect_color_t color = {0.4f, 0.5f, 1.0f, 0.5f};

        effect_template.flags = 0x1d;
        effect_template.color = color;
        effect_template.lifetime = 0.5f;
        effect_template.half_extent.x = 32.0f;
        effect_template.half_extent.y = 32.0f;

        count = 16;
        do {
            effect_template_rotation = (float)(crt_rand() & 0x7f) * 0.049087387f;
            effect_template_vel_x = (float)(crt_rand() % 128 - 64);
            effect_template_vel_y = (float)(crt_rand() % 128 - 64);
            effect_template_scale_step = (float)(crt_rand() % 100) * 0.01f + 0.1f;
            effect_spawn(0, pos);
            --count;
        } while (count != 0);
    }
}
