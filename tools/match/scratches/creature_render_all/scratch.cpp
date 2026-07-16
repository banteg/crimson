#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern float ui_transition_alpha;
extern game_state_id_t game_state_prev;
extern int particles_texture;
extern float camera_offset_x;
extern float camera_offset_y;
extern int perk_id_monster_vision;

void effect_select_texture(int effect_id);
void creature_render_type(int type_id, float transition_alpha);
}

extern "C" void creature_render_all(void)
{
    float transition_alpha = ui_transition_alpha;
    if (transition_alpha <= 0.0f
        || game_state_id == GAME_STATE_MODS_MENU
        || game_state_id == GAME_STATE_PLUGIN_RUNTIME
        || game_state_prev == GAME_STATE_MODS_MENU
        || game_state_prev == GAME_STATE_PLUGIN_RUNTIME) {
        return;
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(0x10);
    grim_interface_ptr->grim_set_color(0.0f, 0.0f, 0.0f, 1.0f);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_begin_batch();

    for (int creature_index = 0; creature_index < 384; creature_index++) {
        creature_t *creature = &creature_pool[creature_index];
        float *lifecycle_stage = &creature->lifecycle_stage;
        if (creature->active) {
            if (perk_count_get(perk_id_monster_vision) != 0) {
                float alpha = *lifecycle_stage < 0.0f
                    ? (*lifecycle_stage + 10.0f) * 0.1f
                    : 1.0f;
                if (alpha > 1.0f) {
                    alpha = 1.0f;
                } else if (alpha < 0.0f) {
                    alpha = 0.0f;
                }
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 0.0f, alpha * transition_alpha);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + lifecycle_stage[1] - 45.0f,
                    camera_offset_y + lifecycle_stage[2] - 45.0f,
                    90.0f,
                    90.0f);
            }

            if (creature->collision_flag) {
                float alpha = *lifecycle_stage < 0.0f
                    ? (*lifecycle_stage + 10.0f) * 0.1f
                    : 1.0f;
                grim_interface_ptr->grim_set_color(
                    0.0f, 0.0f, 0.0f, alpha * transition_alpha);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + lifecycle_stage[1] - 40.0f,
                    camera_offset_y + lifecycle_stage[2] - 40.0f,
                    80.0f,
                    80.0f);
            }

            if ((creature->flags & CREATURE_FLAG_SELF_DAMAGE_TICK) != 0) {
                float alpha = *lifecycle_stage < 0.0f
                    ? (*lifecycle_stage + 10.0f) * 0.1f
                    : 1.0f;
                grim_interface_ptr->grim_set_color(
                    1.0f, 0.0f, 0.0f, alpha * transition_alpha);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + lifecycle_stage[1] - 30.0f,
                    camera_offset_y + lifecycle_stage[2] - 30.0f,
                    60.0f,
                    60.0f);
            }
        }

    }

    grim_interface_ptr->grim_end_batch();

    creature_render_type(CREATURE_TYPE_ZOMBIE, transition_alpha);
    creature_render_type(CREATURE_TYPE_SPIDER_SP1, transition_alpha);
    creature_render_type(CREATURE_TYPE_SPIDER_SP2, transition_alpha);
    creature_render_type(CREATURE_TYPE_ALIEN, transition_alpha);
    creature_render_type(CREATURE_TYPE_LIZARD, transition_alpha);

    if (bonus_freeze_timer > 0.0f) {
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
        grim_interface_ptr->grim_bind_texture(particles_texture, 0);
        effect_select_texture(0x0e);
        grim_interface_ptr->grim_set_color(0.0f, 0.0f, 0.0f, 1.0f);
        grim_interface_ptr->grim_set_rotation(0.0f);

        float freeze_alpha = 1.0f;
        if (bonus_freeze_timer < 1.0f) {
            freeze_alpha = bonus_freeze_timer;
        }
        if (freeze_alpha > 1.0f) {
            freeze_alpha = 1.0f;
        } else if (freeze_alpha < 0.0f) {
            freeze_alpha = 0.0f;
        }
        freeze_alpha = freeze_alpha * transition_alpha * 0.7f;

        grim_interface_ptr->grim_begin_batch();

        for (int creature_index = 0; creature_index < 384; creature_index++) {
            creature_t *creature = &creature_pool[creature_index];
            if (creature->active) {
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, freeze_alpha);
                grim_interface_ptr->grim_set_rotation(
                    (float)creature_index * 0.01f + creature->heading);
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + creature->pos_x
                        - creature->size * 0.5f,
                    camera_offset_y + creature->pos_y
                        - creature->size * 0.5f,
                    creature->size,
                    creature->size);
            }

        }

        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
    }

    grim_interface_ptr->grim_set_color(0.0f, 1.0f, 1.0f, 1.0f);
}
