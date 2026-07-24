#include <math.h>
#include <stddef.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct bonus_render_color_t {
    float r;
    float g;
    float b;
    float a;

    bonus_render_color_t(float red, float green, float blue, float alpha)
        : r(red), g(green), b(blue), a(alpha) {}
};

struct bonus_render_particle_t {
    unsigned char active;
    unsigned char render_flag;
    unsigned char _pad0[2];
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    union {
        float color_r;
        float size_scale;
    } value_14;
    float color_g;
    float color_b;
    float color_a;
    float progress;
    float angle;
    float rotation;
    unsigned char style_id;
    unsigned char _pad1[3];
    int target_id;
};

extern "C" {
extern float ui_transition_alpha;
extern game_state_id_t game_state_prev;
extern float bonus_render_anim_phase;
extern int particles_texture;
extern int bonus_texture;
extern int ui_weapon_icons_texture;
extern float camera_offset_x;
extern float camera_offset_y;
extern float player_aim_x[];
extern int config_player_count;
extern int config_screen_width;
extern unsigned char config_fx_detail_flag1;
extern unsigned char config_fx_detail_flag2;
extern int frame_dt_ms;
extern int perk_id_telekinetic;
extern int telekinetic_bonus_hover_timer_ms[];
extern float sprite_effect_uv_u;
extern float sprite_effect_uv_v;

void effect_select_texture(int effect_id);
char *bonus_label_for_entry(bonus_entry_t *entry);
void bonus_apply(int player_index, bonus_entry_t *entry);
void effects_render(void);
}

static __inline void bonus_render_clamp(float *value)
{
    if (*value < 0.0f) {
        *value = 0.0f;
    } else if (*value > 1.0f) {
        *value = 1.0f;
    }
}

static __inline float bonus_render_icon_fade(const bonus_entry_t *entry)
{
    if (entry->time.time_left < 0.5f) {
        return entry->time.time_left + entry->time.time_left;
    }

    float age = entry->time.time_max - entry->time.time_left;
    if (age < 0.5f) {
        return age + age;
    }
    return 1.0f;
}

static __inline float bonus_render_bubble_fade(const bonus_entry_t *entry)
{
    float fade = 1.0f;
    if (entry->time.time_left < 2.0f) {
        if ((float)sin(entry->time.time_left * 18.849556f) > 0.0f) {
            fade = entry->time.time_left * 0.25f;
        } else {
            fade = entry->time.time_left * 0.5f;
        }
    }

    float age = entry->time.time_max - entry->time.time_left;
    if (age < 0.5f) {
        fade = age + age;
    }
    return fade;
}

static __inline float bonus_render_distance(
    const vec2f_t *lhs,
    const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    return (float)sqrt(dy * dy + dx * dx);
}

extern "C" void bonus_render(void)
{
    int bonus_index;
    float transition_alpha = ui_transition_alpha;
    bonus_render_color_t color(0.47f, 0.47f, 0.47f, 1.0f);

    if (transition_alpha <= 0.0f) {
        return;
    }
    if (game_state_id == GAME_STATE_MODS_MENU
        || game_state_id == GAME_STATE_PLUGIN_RUNTIME) {
        return;
    }
    if (game_state_prev == GAME_STATE_MODS_MENU
        || game_state_prev == GAME_STATE_PLUGIN_RUNTIME) {
        return;
    }

    bonus_render_anim_phase += frame_dt * 1.3f;
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(16);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);

    color = bonus_render_color_t(0.7f, 0.8f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_bind_texture(bonus_texture, 0);
    grim_interface_ptr->grim_set_rotation(0.0f);
    color = bonus_render_color_t(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_begin_batch();

    for (bonus_index = 0; bonus_index < 16; ++bonus_index) {
        bonus_entry_t *entry = &bonus_pool[bonus_index];
        if (entry->bonus_id == BONUS_ID_NONE) {
            continue;
        }

        float bubble_alpha = bonus_render_bubble_fade(entry) * 0.9f;
        color.a = bubble_alpha * transition_alpha;
        bonus_render_clamp(&color.r);
        bonus_render_clamp(&color.g);
        bonus_render_clamp(&color.b);
        bonus_render_clamp(&color.a);
        grim_interface_ptr->grim_set_color_ptr(&color.r);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_atlas_frame(4, 0);
        grim_interface_ptr->grim_draw_quad(
            camera_offset_x + entry->time.pos_x - 16.0f,
            camera_offset_y + entry->time.pos_y - 16.0f,
            32.0f,
            32.0f);

        int icon_id = bonus_meta_table[entry->bonus_id].icon_id;
        if (icon_id >= 0) {
            float fade = bonus_render_icon_fade(entry);
            color.a = transition_alpha;
            float icon_scale = fade * transition_alpha;
            bonus_render_clamp(&color.r);
            bonus_render_clamp(&color.g);
            bonus_render_clamp(&color.b);
            if (transition_alpha > 1.0f) {
                color.a = 1.0f;
            }
            grim_interface_ptr->grim_set_color_ptr(&color.r);

            float index_phase = (float)bonus_index;
            float pulse_value =
                (float)sin(index_phase + bonus_render_anim_phase);
            icon_scale *=
                (float)pow(pulse_value, 2.0) * 0.25f + 0.75f;
            grim_interface_ptr->grim_set_color_ptr(&color.r);
            grim_interface_ptr->grim_set_rotation(
                (float)sin(
                    index_phase - (float)survival_elapsed_ms * 0.003f)
                * 0.2f);

            if (entry->bonus_id == BONUS_ID_POINTS
                && entry->time.amount == 1000) {
                grim_interface_ptr->grim_set_atlas_frame(4, icon_id + 1);
            } else {
                grim_interface_ptr->grim_set_atlas_frame(4, icon_id);
            }

            float size = icon_scale * 32.0f;
            float half_size = icon_scale * 16.0f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + entry->time.pos_x - half_size,
                camera_offset_y + entry->time.pos_y - half_size,
                size,
                size);
        }
    }
    grim_interface_ptr->grim_end_batch();

    int player_index = 0;
    grim_interface_ptr->grim_bind_texture(ui_weapon_icons_texture, 0);
    grim_interface_ptr->grim_begin_batch();
    for (bonus_index = 0; bonus_index < 16; ++bonus_index) {
        bonus_entry_t *entry = &bonus_pool[bonus_index];
        if (entry->bonus_id != BONUS_ID_WEAPON) {
            continue;
        }

        float fade = bonus_render_icon_fade(entry) * transition_alpha;
        color.a = fade;
        grim_interface_ptr->grim_set_color_ptr(&color.r);
        float pulse_value = (float)sin(bonus_render_anim_phase);
        float icon_scale =
            ((float)pow(pulse_value, 2.0) * 0.25f + 0.75f) * fade;
        grim_interface_ptr->grim_set_color_ptr(&color.r);
        grim_interface_ptr->grim_set_rotation(
            (float)sin(
                (float)bonus_index
                - (float)survival_elapsed_ms * 0.003f));
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_sub_rect(
            8,
            2,
            1,
            weapon_table[entry->time.amount].hud_icon_id * 2);

        float half_width = icon_scale * 30.0f;
        float height = icon_scale * 30.0f;
        grim_interface_ptr->grim_draw_quad(
            camera_offset_x + entry->time.pos_x - half_width,
            camera_offset_y + entry->time.pos_y - icon_scale * 15.0f,
            icon_scale * 60.0f,
            height);
    }
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);

    int *hover_timer = telekinetic_bonus_hover_timer_ms;
    vec2f_t *player_aim = (vec2f_t *)player_aim_x;
    int nearby_bonus_index;
    if (config_player_count > 0) {
        while (1) {
            player_state_t *player = (player_state_t *)(
                (char *)player_aim - offsetof(player_state_t, aim_x));
            if (player->health > 0.0f) {
                nearby_bonus_index = 0;
                bonus_entry_t *nearby_bonus = bonus_pool;
                while (1) {
                    if (nearby_bonus->bonus_id != BONUS_ID_NONE
                        && bonus_render_distance(
                               player_aim,
                               &nearby_bonus->time.position)
                            < 24.0f) {
                        break;
                    }
                    ++nearby_bonus;
                    ++nearby_bonus_index;
                    if ((int)nearby_bonus
                        >= (int)&bonus_pool[16]) {
                        *hover_timer = 0;
                        goto telekinetic_threshold;
                    }
                }

                {
                    if (game_state_id == GAME_STATE_GAMEPLAY) {
                        *hover_timer += frame_dt_ms;
                    }

                    char *label = bonus_label_for_entry(
                        &bonus_pool[nearby_bonus_index]);
                    float label_x =
                        camera_offset_x + player_aim->x + 16.0f;
                    float label_y =
                        camera_offset_y + player_aim->y - 7.0f;
                    float label_width =
                        (float)grim_interface_ptr
                            ->grim_measure_text_width(label);
                    if (label_x + label_width
                        > (float)config_screen_width) {
                        label_x =
                            (float)config_screen_width - label_width;
                    }
                    grim_interface_ptr->grim_draw_text_small(
                        label_x, label_y, label);
                }

telekinetic_threshold:
                if (*hover_timer > 650
                    && perk_count_get(perk_id_telekinetic)
                    && bonus_pool[nearby_bonus_index].state == 0) {
                    break;
                }
            }

            ++player_index;
            player_aim = (vec2f_t *)(
                (char *)player_aim + sizeof(player_state_t));
            ++hover_timer;
            if (player_index >= config_player_count) {
                break;
            }
        }

        if (player_index < config_player_count) {
            bonus_entry_t *entry = &bonus_pool[nearby_bonus_index];
            bonus_apply(player_index, entry);
            entry->state = 1;
            entry->time.time_left = 0.5f;
            telekinetic_bonus_hover_timer_ms[player_index] = 0;
        }
    }

    bonus_render_particle_t *particle =
        (bonus_render_particle_t *)particle_pool;
    if (config_fx_detail_flag1) {
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 2u);
        grim_interface_ptr->grim_bind_texture(particles_texture, 0);
        effect_select_texture(13);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.065f);
        grim_interface_ptr->grim_begin_batch();

        for (int particle_index = 0;
             particle_index < 0x80;
             ++particle_index) {
            bonus_render_particle_t *glow =
                &particle[particle_index];
            if (glow->active
                && particle_index % 2 == 0
                && glow->style_id != 8) {
                float half_size =
                    ((float)sin((1.0f - glow->progress) * 1.5707964f)
                         + 0.1f)
                        * 55.0f
                    + 4.0f;
                if (half_size < 16.0f) {
                    half_size = 16.0f;
                }
                float size = half_size + half_size;
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + glow->pos_x - half_size,
                    camera_offset_y + glow->pos_y - half_size,
                    size,
                    size);
            }
        }
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_bind_texture(particles_texture, 0);
    effect_select_texture(12);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_begin_batch();
    for (int sprite_index = 0;
         sprite_index < 0x80;
         ++sprite_index) {
        bonus_render_particle_t *sprite =
            &particle[sprite_index];
        if (sprite->active && sprite->style_id != 8) {
            grim_interface_ptr->grim_set_rotation(sprite->rotation);
            grim_interface_ptr->grim_set_color(
                sprite->value_14.color_r,
                sprite->color_g,
                sprite->color_b,
                sprite->color_a);
            float half_size =
                (float)sin((1.0f - sprite->progress) * 1.5707964f)
                * 24.0f;
            if (sprite->style_id == 1) {
                half_size *= 0.8f;
            }
            if (half_size < 2.0f) {
                half_size = 2.0f;
            }
            float size = half_size + half_size;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + sprite->pos_x - half_size,
                camera_offset_y + sprite->pos_y - half_size,
                size,
                size);
        }
    }
    grim_interface_ptr->grim_end_batch();

    effect_select_texture(2);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_begin_batch();
    for (int beam_index = 0;
         beam_index < 0x80;
         ++beam_index) {
        bonus_render_particle_t *beam =
            &particle[beam_index];
        if (beam->active && beam->style_id == 8) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, beam->color_a);
            float phase_size = (float)sin(beam->rotation) * 3.0f;
            float half_width = 15.0f - phase_size;
            float half_height =
                (phase_size + 15.0f)
                * beam->value_14.size_scale
                * 7.0f;
            half_width =
                half_width * beam->value_14.size_scale * 7.0f;
            float height = half_height + half_height;
            float width = half_width + half_width;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + beam->pos_x - half_width,
                camera_offset_y + beam->pos_y - half_height,
                width,
                height);
        }
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x14, 6u);

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_begin_batch();
    for (int secondary_index = 0;
         secondary_index < 0x40;
         ++secondary_index) {
        secondary_projectile_t *secondary =
            &secondary_projectile_pool[secondary_index];
        if (secondary->active
            && secondary->pos.vx.vy.type_id
                == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
            grim_interface_ptr->grim_set_color(
                1.0f,
                0.6f,
                0.1f,
                1.0f - secondary->pos.vx.vel_x);
            float size =
                secondary->pos.vx.vy.vel_y
                * secondary->pos.vx.vel_x
                * 64.0f;
            float half_size = size * 0.5f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + secondary->pos_x - half_size,
                camera_offset_y + secondary->pos.pos_y - half_size,
                size,
                size);

            grim_interface_ptr->grim_set_color(
                1.0f,
                0.6f,
                0.1f,
                (1.0f - secondary->pos.vx.vel_x) * 0.3f);
            size =
                secondary->pos.vx.vy.vel_y
                * secondary->pos.vx.vel_x
                * 200.0f;
            half_size = size * 0.5f;
            grim_interface_ptr->grim_draw_quad(
                camera_offset_x + secondary->pos_x - half_size,
                camera_offset_y + secondary->pos.pos_y - half_size,
                size,
                size);
        }
    }
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x14, 6u);

    if (config_fx_detail_flag2) {
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
        grim_interface_ptr->grim_bind_texture(particles_texture, 0);
        grim_interface_ptr->grim_set_uv(
            sprite_effect_uv_u,
            sprite_effect_uv_v,
            sprite_effect_uv_u + 0.25f,
            sprite_effect_uv_v + 0.25f);
        grim_interface_ptr->grim_begin_batch();
        for (int effect_index = 0;
             effect_index < 0x180;
             ++effect_index) {
            sprite_effect_t *effect =
                &sprite_effect_pool[effect_index];
            if (effect->active) {
                float size = effect->scale;
                grim_interface_ptr->grim_set_rotation(effect->rotation);
                grim_interface_ptr->grim_set_color(
                    effect->color_r,
                    effect->color_g,
                    effect->color_b,
                    effect->color_a);
                float half_size = size * 0.5f;
                grim_interface_ptr->grim_draw_quad(
                    camera_offset_x + effect->pos_x - half_size,
                    camera_offset_y + effect->pos_y - half_size,
                    size,
                    size);
            }
        }
        grim_interface_ptr->grim_end_batch();
    }

    effects_render();
}
