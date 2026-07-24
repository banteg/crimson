#define creature_apply_damage creature_apply_damage_pointer_abi
#include "crimsonland_gameplay.h"
#undef creature_apply_damage
#include <stddef.h>

struct damage_vec2_t {
    float x;
    float y;

    damage_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    damage_vec2_t operator*(float scale) const
    {
        return damage_vec2_t(x * scale, y * scale);
    }
};

extern "C" {
extern int perk_id_uranium_filled_bullets;
extern int perk_id_barrel_greaser;
extern int perk_id_doctor;
extern int perk_id_pyromaniac;
extern int perk_id_ion_gun_master;
extern creature_type_table_t creature_type_table;

void creature_handle_death(int creature_id, unsigned char keep_corpse);
}

extern "C" int creature_apply_damage(
    int creature_id,
    float damage,
    int damage_type,
    const vec2f_t *impulse)
{
    creature_pool[creature_id].hit_flash_timer = 0.2f;

    if (damage_type == 1) {
        if (perk_count_get(perk_id_uranium_filled_bullets) != 0) {
            damage += damage;
        }

        if (perk_count_get(perk_id_living_fortress) != 0) {
            int player_count = config_blob.player_count;
            if (player_count > 0) {
                float *living_fortress_timer =
                    &player_state_table[0].living_fortress_timer;
                do {
                    player_state_t *player = (player_state_t *)(
                        (char *)living_fortress_timer
                        - offsetof(player_state_t, living_fortress_timer));
                    if (player->health > 0.0f) {
                        damage *= *living_fortress_timer * 0.05f + 1.0f;
                    }
                    living_fortress_timer += 0xd8;
                    --player_count;
                } while (player_count != 0);
            }
        }

        if (perk_count_get(perk_id_barrel_greaser) != 0) {
            damage *= 1.4f;
        }
        if (perk_count_get(perk_id_doctor) != 0) {
            damage *= 1.2f;
        }

        if ((creature_pool[creature_id].flags
                & CREATURE_FLAG_ANIM_PING_PONG) == 0) {
            float turn =
                (float)((crt_rand() & 0x7f) - 0x40) * 0.002f
                / (creature_pool[creature_id].size * 0.025f);
            if (turn > 1.57079637f) {
                turn = 1.57079637f;
            }
            creature_pool[creature_id].heading += turn;
        }
    } else if (damage_type == 7
        && perk_count_get(perk_id_ion_gun_master) != 0) {
        damage *= 1.2f;
    }

    if (creature_pool[creature_id].health > 0.0f) {
        if (damage_type == 4
            && perk_count_get(perk_id_pyromaniac) != 0) {
            damage *= 1.5f;
            crt_rand();
        }

        creature_pool[creature_id].health -= damage;
        creature_pool[creature_id].vel_x -= impulse->x;
        creature_pool[creature_id].vel_y -= impulse->y;

        if (creature_pool[creature_id].health <= 0.0f) {
            creature_pool[creature_id].lifecycle_stage -= frame_dt;
            creature_handle_death(creature_id, 1);

            damage_vec2_t doubled_impulse =
                *(const damage_vec2_t *)impulse * 2.0f;
            creature_pool[creature_id].vel_x -= doubled_impulse.x;
            creature_pool[creature_id].vel_y -= doubled_impulse.y;

            if ((creature_pool[creature_id].flags
                    & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0) {
                effect_color_t color = {0.8f, 0.8f, 0.3f, 0.5f};
                effect_template.flags = 0x1d;
                effect_template.color = color;
                effect_template.lifetime = 0.7f;
                effect_template.half_width = 36.0f;
                effect_template.half_height = 36.0f;

                int count = 5;
                do {
                    effect_template.rotation =
                        (float)(crt_rand() & 0x7f) * 0.049087387f;
                    effect_template.vel_x =
                        (float)((crt_rand() & 0x7f) - 0x40);
                    effect_template.vel_y =
                        (float)((crt_rand() & 0x7f) - 0x40);
                    effect_template.scale_step =
                        (float)(crt_rand() % 140) * 0.01f + 0.3f;
                    effect_spawn(
                        0,
                        &creature_pool[creature_id].position);
                    --count;
                } while (count != 0);
            } else {
                sfx_play_panned(
                    creature_type_table[
                        creature_pool[creature_id].type_id
                    ].sfx_bank_a[crt_rand() % 4],
                    &creature_pool[creature_id].position,
                    1.0f);
            }
        }
    } else {
        creature_pool[creature_id].lifecycle_stage -= frame_dt * 15.0f;
    }

    return creature_pool[creature_id].health <= 0.0f;
}
