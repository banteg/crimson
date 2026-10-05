#include <string.h>

#include "crimsonland_gameplay.h"

#include "crimsonland_game_state_owner.h"

#define survival_first_kill_positions \
    gameplay_run_state.survival_first_kill_pos
#define survival_first_kill_count \
    gameplay_run_state.survival_first_kill_count
extern unsigned char survival_reward_fire_seen;
extern unsigned char survival_shrinkifier_handout_enabled;
extern int creature_kill_count;
extern int perk_id_bloody_mess_quick_learner;

extern void bonus_try_spawn_on_kill(const vec2f_t *pos);
extern void fx_queue_add_random(vec2f_t *pos);

void creature_handle_death(int creature_id, unsigned char keep_corpse)
{
    creature_t *creature = &creature_pool[creature_id];
    int creature_flags = creature->flags;
    if ((creature_flags & CREATURE_FLAG_BONUS_ON_DEATH) != 0) {
        bonus_spawn_at(
            &creature->position,
            (bonus_id_t)creature->bonus_args.bonus_id,
            creature->bonus_args.amount_override
        );
    }

    if (survival_first_kill_count < 6) {
        if (survival_first_kill_count < 3) {
            survival_first_kill_positions[survival_first_kill_count].x =
                creature->position.x;
            survival_first_kill_positions[survival_first_kill_count].y =
                creature->position.y;
        }
        ++survival_first_kill_count;
        if (survival_first_kill_count == 3) {
            survival_reward_fire_seen = 0;
            survival_shrinkifier_handout_enabled = 0;
        }
    }

    if (!creature_pool[creature_id].active) {
        return;
    }

    if ((creature->flags & CREATURE_FLAG_SPAWNER) != 0) {
        creature_spawn_slot_table[creature->link_index].owner = 0;
    }

    if ((creature->flags & CREATURE_FLAG_SPLIT_ON_DEATH) != 0
        && creature->size > 35.0f) {
        int child_id = creature_alloc_slot();
        memcpy(&creature_pool[child_id], creature, sizeof(creature_t));
        creature_pool[child_id].phase_seed = crt_rand() & 0xff;
        creature_pool[child_id].heading =
            creature->heading - 1.57079637f;
        creature_pool[child_id].health = creature->max_health * 0.25f;
        creature_pool[child_id].reward_value *= 0.666666687f;
        creature_pool[child_id].size -= 8.0f;
        creature_pool[child_id].move_speed += 0.1f;
        creature_pool[child_id].contact_damage *= 0.7f;
        creature_pool[child_id].death_timer = 16.0f;

        child_id = creature_alloc_slot();
        memcpy(&creature_pool[child_id], creature, sizeof(creature_t));
        creature_pool[child_id].phase_seed = crt_rand() & 0xff;
        creature_pool[child_id].heading =
            creature->heading + 1.57079637f;
        creature_pool[child_id].health = creature->max_health * 0.25f;
        creature_pool[child_id].size -= 8.0f;
        creature_pool[child_id].move_speed += 0.1f;
        creature_pool[child_id].reward_value *= 0.666666687f;
        creature_pool[child_id].death_timer = 16.0f;
        creature_pool[child_id].contact_damage *= 0.7f;

        effect_spawn_burst(
            &creature->position,
            8);
    }

    if (keep_corpse) {
        creature->death_timer -= frame_dt;
    } else {
        creature->active = 0;
    }

    {
        int quick_learner = perk_id_bloody_mess_quick_learner;
        if (player_state_table[0].perk_counts[quick_learner] > 0) {
            player_state_table[0].experience +=
                (int)(creature->reward_value * 1.3f);
        } else {
            player_state_table[0].experience =
                (int)((float)player_state_table[0].experience
                    + creature->reward_value);
        }

        if (bonus_double_xp_timer > 0.0f) {
            if (player_state_table[0].perk_counts[quick_learner] > 0) {
                player_state_table[0].experience +=
                    (int)(creature->reward_value * 1.3f);
            } else {
                player_state_table[0].experience =
                    (int)((float)player_state_table[0].experience
                        + creature->reward_value);
            }
        }
    }

    if (!scripted_burst_active) {
        bonus_try_spawn_on_kill(&creature->position);
    }

    if (bonus_freeze_timer > 0.0f) {
        vec2f_t *pos = &creature->position;
        int i;
        for (i = 0; i < 8; i++) {
            effect_spawn_freeze_shard(
                pos,
                (float)(crt_rand() % 612) * 0.01f
            );
        }

        effect_spawn_freeze_shatter(
            pos,
            (float)(crt_rand() % 612) * 0.01f
        );
        ++creature_kill_count;
        creature->active = 0;
        fx_queue_add_random(pos);
    }
}
