#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"
#include <stddef.h>

extern IGrim2D_cpp *grim_interface_ptr;

struct creature_render_vec2_t {
    float x;
    float y;

    creature_render_vec2_t() {}

    creature_render_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    creature_render_vec2_t operator+(
        const creature_render_vec2_t &other) const
    {
        return creature_render_vec2_t(x + other.x, y + other.y);
    }

    creature_render_vec2_t operator-(
        const creature_render_vec2_t &other) const
    {
        return creature_render_vec2_t(x - other.x, y - other.y);
    }

};

struct creature_render_color_t {
    float r;
    float g;
    float b;
    float a;

    creature_render_color_t() {}

    creature_render_color_t(
        float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" {
extern creature_type_table_t creature_type_table;
extern int perk_id_monster_vision;
extern creature_render_vec2_t camera_offset;
extern float creature_max_health[];
}

extern "C" void creature_render_type(int type_id, float transition_alpha)
{
    creature_render_color_t color;
    creature_render_vec2_t draw_pos;

    grim_interface_ptr->grim_bind_texture(
        creature_type_table[type_id].texture_handle, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);

    if (config_blob.shadows_enabled
        && perk_count_get(perk_id_monster_vision) == 0) {
        grim_interface_ptr->grim_set_config_var(0x13, 1u);
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
        grim_interface_ptr->grim_begin_batch();

        for (int creature_index = 0; creature_index < 384; creature_index++) {
            creature_t *creature = &creature_pool[creature_index];
            if (!creature->active || creature->type_id != type_id) {
                continue;
            }

            int flags = creature->flags;
            creature_render_color_t *tint =
                (creature_render_color_t *)&creature->color;
            color = *tint;
            color.a *= 0.4f;

            int frame;
            if ((flags & CREATURE_FLAG_ANIM_PING_PONG) != 0
                && (flags & CREATURE_FLAG_ANIM_LONG_STRIP) == 0) {
                frame = (int)(creature->anim_phase + 0.5f) % 16;
                if (frame > 7) {
                    frame = 15 - frame;
                }
                frame += creature_type_table[type_id].base_frame + 16;
                grim_interface_ptr->grim_set_atlas_frame(8, frame);

                if (creature->lifecycle_stage < 0.0f) {
                    color.a += creature->lifecycle_stage * 0.1f;
                    if (color.a < 0.0f) {
                        color.a = 0.0f;
                    }
                }
            } else {
                if (creature->lifecycle_stage < 16.0f) {
                    if (creature->lifecycle_stage < 0.0f) {
                        frame = creature_type_table[type_id].base_frame + 15;
                        color.a += creature->lifecycle_stage * 0.5f;
                        if (color.a < 0.0f) {
                            color.a = 0.0f;
                        }
                    } else {
                        frame = (int)((float)(
                            creature_type_table[type_id].base_frame + 15)
                            - creature->lifecycle_stage);
                    }
                } else {
                    frame = (int)(creature->anim_phase + 0.5f);
                    if ((creature_type_table[type_id].anim_flags & 1) != 0
                        && frame > 15) {
                        frame = 31 - frame;
                    }
                }
                if ((flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0) {
                    frame += 32;
                }
                grim_interface_ptr->grim_set_atlas_frame(8, frame);
            }

            color.a *= transition_alpha;
            grim_interface_ptr->grim_set_color_ptr((float *)&color);
            grim_interface_ptr->grim_set_rotation(
                creature->heading - 1.57079637f);

            draw_pos =
                camera_offset
                + *(creature_render_vec2_t *)&creature->position
                - creature_render_vec2_t(
                    creature->size * 0.5f + 0.7f,
                    creature->size * 0.5f + 0.7f);
            float draw_size = creature->size * 1.07f;
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x, draw_pos.y, draw_size, draw_size);
        }

        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_begin_batch();

    if (bonus_energizer_timer > 0.0f) {
        float *max_health = creature_max_health;
        do {
            creature_t *creature = (creature_t *)(
                (char *)max_health - offsetof(creature_t, max_health));
            if (creature->active && creature->type_id == type_id) {

            if (*max_health < 500.0f) {
                float energizer_alpha = bonus_energizer_timer < 1.0f
                    ? bonus_energizer_timer
                    : 1.0f;
                float original_alpha = 1.0f - energizer_alpha;
                float half_energizer_alpha = energizer_alpha * 0.5f;
                color.r = original_alpha * creature->tint_r
                    + half_energizer_alpha;
                color.g = original_alpha * creature->tint_g
                    + half_energizer_alpha;
                color.b = original_alpha * creature->tint_b
                    + energizer_alpha;
                color.a = original_alpha * creature->tint_a
                    + energizer_alpha;
            } else {
                creature_render_color_t *tint =
                    (creature_render_color_t *)&creature->color;
                color = *tint;
            }

            int flags = creature->flags;
            int frame;
            if ((flags & CREATURE_FLAG_ANIM_PING_PONG) != 0
                && (flags & CREATURE_FLAG_ANIM_LONG_STRIP) == 0) {
                frame = (int)(creature->anim_phase + 0.5f) % 16;
                if (frame > 7) {
                    frame = 15 - frame;
                }
                frame += creature_type_table[type_id].base_frame + 16;
                grim_interface_ptr->grim_set_atlas_frame(8, frame);

                if (creature->lifecycle_stage < 0.0f) {
                    color.a += creature->lifecycle_stage * 0.1f;
                    if (color.a < 0.0f) {
                        color.a = 0.0f;
                    }
                }
            } else {
                if (creature->lifecycle_stage < 16.0f) {
                    if (creature->lifecycle_stage < 0.0f) {
                        frame = creature_type_table[type_id].base_frame + 15;
                        color.a += creature->lifecycle_stage * 0.1f;
                        if (color.a < 0.0f) {
                            color.a = 0.0f;
                        }
                    } else {
                        frame = (int)((float)(
                            creature_type_table[type_id].base_frame + 15)
                            - creature->lifecycle_stage);
                    }
                } else {
                    frame = (int)(creature->anim_phase + 0.5f);
                    if ((creature_type_table[type_id].anim_flags & 1) != 0
                        && frame > 15) {
                        frame = 31 - frame;
                    }
                }
                if ((flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0) {
                    frame += 32;
                }
                grim_interface_ptr->grim_set_atlas_frame(8, frame);
            }

            color.a *= transition_alpha;
            grim_interface_ptr->grim_set_color_ptr((float *)&color);
            grim_interface_ptr->grim_set_rotation(
                creature->heading - 1.57079637f);

            draw_pos =
                camera_offset
                + *(creature_render_vec2_t *)&creature->position
                - creature_render_vec2_t(
                    creature->size * 0.5f,
                    creature->size * 0.5f);
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x, draw_pos.y, creature->size, creature->size);

            if (creature->lifecycle_stage < -10.0f) {
                creature->active = 0;
                if ((creature->flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
                    creature_spawn_slot_table[creature->link_index].owner = 0;
                }
            }
            }
            max_health += 38;
        } while ((int)max_health < (int)(creature_max_health + 384 * 38));
    } else {
        for (int creature_index = 0; creature_index < 384; creature_index++) {
            creature_t *creature = &creature_pool[creature_index];
            if (!creature->active || creature->type_id != type_id) {
                continue;
            }

            int flags = creature->flags;
            creature_render_color_t *tint =
                (creature_render_color_t *)&creature->color;
            color = *tint;

            int frame;
            if ((flags & CREATURE_FLAG_ANIM_PING_PONG) != 0
                && (flags & CREATURE_FLAG_ANIM_LONG_STRIP) == 0) {
                frame = (int)(creature->anim_phase + 0.5f) % 16;
                if (frame > 7) {
                    frame = 15 - frame;
                }
                frame += creature_type_table[type_id].base_frame + 16;
                grim_interface_ptr->grim_set_atlas_frame(8, frame);

                if (creature->lifecycle_stage < 0.0f) {
                    color.a += creature->lifecycle_stage * 0.1f;
                    if (color.a < 0.0f) {
                        color.a = 0.0f;
                    }
                }
            } else {
                if (creature->lifecycle_stage < 16.0f) {
                    if (creature->lifecycle_stage < 0.0f) {
                        frame = creature_type_table[type_id].base_frame + 15;
                        color.a += creature->lifecycle_stage * 0.1f;
                        if (color.a < 0.0f) {
                            color.a = 0.0f;
                        }
                    } else {
                        frame = (int)((float)(
                            creature_type_table[type_id].base_frame + 15)
                            - creature->lifecycle_stage);
                    }
                } else {
                    frame = (int)(creature->anim_phase + 0.5f);
                    if ((creature_type_table[type_id].anim_flags & 1) != 0
                        && frame > 15) {
                        frame = 31 - frame;
                    }
                }
                if ((flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0) {
                    frame += 32;
                }
                grim_interface_ptr->grim_set_atlas_frame(8, frame);
            }

            color.a *= transition_alpha;
            grim_interface_ptr->grim_set_color_ptr((float *)&color);
            grim_interface_ptr->grim_set_rotation(
                creature->heading - 1.57079637f);

            draw_pos =
                camera_offset
                + *(creature_render_vec2_t *)&creature->position
                - creature_render_vec2_t(
                    creature->size * 0.5f,
                    creature->size * 0.5f);
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x, draw_pos.y, creature->size, creature->size);

            if (creature->lifecycle_stage < -10.0f) {
                creature->active = 0;
                if ((creature->flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
                    creature_spawn_slot_table[creature->link_index].owner = 0;
                }
            }
        }
    }

    grim_interface_ptr->grim_end_batch();

    if (config_blob.violence_disabled) {
        grim_interface_ptr->grim_set_config_var(0x14, 2u);

        color = creature_render_color_t(1.0f, 1.0f, 1.0f, 1.0f);

        grim_interface_ptr->grim_begin_batch();
        for (int creature_index = 0; creature_index < 384; creature_index++) {
            creature_t *creature = &creature_pool[creature_index];
            if (!creature->active
                || creature->type_id != type_id
                || creature->hit_flash_timer <= 0.0f) {
                continue;
            }

            color.a = creature->hit_flash_timer * 5.0f;
            if (color.a > 1.0f) {
                color.a = 1.0f;
            }

            int flags = creature->flags;
            int frame;
            if ((flags & CREATURE_FLAG_ANIM_PING_PONG) != 0
                && (flags & CREATURE_FLAG_ANIM_LONG_STRIP) == 0) {
                frame = (int)(creature->anim_phase + 0.5f) % 16;
                if (frame > 7) {
                    frame = 15 - frame;
                }
                frame += creature_type_table[type_id].base_frame + 16;
                grim_interface_ptr->grim_set_atlas_frame(8, frame);
            } else {
                if (creature->lifecycle_stage < 16.0f) {
                    if (creature->lifecycle_stage < 0.0f) {
                        frame = creature_type_table[type_id].base_frame + 15;
                    } else {
                        frame = (int)((float)(
                            creature_type_table[type_id].base_frame + 15)
                            - creature->lifecycle_stage);
                    }
                } else {
                    frame = (int)(creature->anim_phase + 0.5f);
                    if ((creature_type_table[type_id].anim_flags & 1) != 0
                        && frame > 15) {
                        frame = 31 - frame;
                    }
                    if ((flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0) {
                        frame += 32;
                    }
                }
                grim_interface_ptr->grim_set_atlas_frame(8, frame);
            }

            color.a *= transition_alpha;
            grim_interface_ptr->grim_set_color_ptr((float *)&color);
            grim_interface_ptr->grim_set_rotation(
                creature->heading - 1.57079637f);

            draw_pos =
                camera_offset
                + *(creature_render_vec2_t *)&creature->position
                - creature_render_vec2_t(
                    creature->size * 0.5f,
                    creature->size * 0.5f);
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x, draw_pos.y, creature->size, creature->size);
            grim_interface_ptr->grim_draw_quad(
                draw_pos.x, draw_pos.y, creature->size, creature->size);
        }

        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
    }

}
