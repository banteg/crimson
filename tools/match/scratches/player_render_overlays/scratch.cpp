#include <math.h>

typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct player_render_vec2_t {
    float x;
    float y;

    player_render_vec2_t() {}

    player_render_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    player_render_vec2_t operator+(
        const player_render_vec2_t &other) const
    {
        return player_render_vec2_t(x + other.x, y + other.y);
    }

    player_render_vec2_t operator-(
        const player_render_vec2_t &other) const
    {
        return player_render_vec2_t(x - other.x, y - other.y);
    }

    player_render_vec2_t operator-(float value) const
    {
        return player_render_vec2_t(x - value, y - value);
    }

    player_render_vec2_t operator*(float scale) const
    {
        return player_render_vec2_t(x * scale, y * scale);
    }
};

extern "C" {
extern float ui_transition_alpha;
extern unsigned char player_overlay_suppressed_latch;
extern game_state_id_t game_state_id;
extern game_state_id_t game_state_prev;
extern int perk_id_radioactive;
extern int player_overlay_auto_target_line_perk_id;
extern int config_player_count;
extern int render_overlay_player_index;
extern float game_time_s;

extern int particles_texture;
extern int muzzle_flash_texture;
extern int projectile_texture;
extern creature_type_table_t creature_type_table;

extern player_render_vec2_t camera_offset;
extern player_render_vec2_t render_scratch_f0;
extern player_render_vec2_t render_scratch_f2;
extern player_render_vec2_t effect_uv8[];
extern player_render_vec2_t player_overlay_torso_uv8[];
extern player_state_t player_state_table[];
extern weapon_stats_t weapon_table[];
extern creature_t creature_pool[];

int perk_count_get(int perk_id);
void effect_select_texture(int effect_id);
vec2f_t *__stdcall D3DXVec2Normalize(
    vec2f_t *dst,
    const vec2f_t *src);
}

static __inline void player_render_set_uv(player_render_vec2_t *table, int frame)
{
    render_scratch_f0 = table[frame];
    render_scratch_f2 =
        table[frame] + player_render_vec2_t(0.125f, 0.125f);
    grim_interface_ptr->grim_set_uv(
        render_scratch_f0.x,
        render_scratch_f0.y,
        render_scratch_f2.x,
        render_scratch_f2.y);
}

static __inline void player_render_set_tint(float transition_alpha)
{
    if (config_player_count == 1) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, transition_alpha);
    } else if (render_overlay_player_index == 0) {
        grim_interface_ptr->grim_set_color(
            0.3f, 0.3f, 1.0f, transition_alpha);
    } else {
        grim_interface_ptr->grim_set_color(
            1.0f, 0.55f, 0.35f, transition_alpha);
    }
}

static __inline float player_render_distance(
    const player_render_vec2_t &from,
    const player_render_vec2_t &to)
{
    float dx = to.x - from.x;
    float dy = to.y - from.y;
    return (float)sqrt(dy * dy + dx * dx);
}

extern "C" void player_render_overlays(void)
{
    float transition_alpha = ui_transition_alpha;
    float half_size;
    float sprite_size;
    player_render_vec2_t effect_offset;
    player_render_vec2_t direction;

    if (player_overlay_suppressed_latch) {
        return;
    }
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

    if (perk_count_get(perk_id_radioactive)) {
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 2u);
        grim_interface_ptr->grim_bind_texture(particles_texture, 0);
        effect_select_texture(16);
        grim_interface_ptr->grim_set_color(
            0.3f,
            0.6f,
            0.3f,
            ((float)sin(game_time_s) + 1.0f) * 0.1875f
                    * transition_alpha
                + 0.25f * transition_alpha);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_begin_batch();
        float aura_y =
            camera_offset.y
            + player_state_table[render_overlay_player_index].pos_y
            - 50.0f;
        float aura_x =
            camera_offset.x
            + player_state_table[render_overlay_player_index].pos_x
            - 50.0f;
        grim_interface_ptr->grim_draw_quad(
            aura_x, aura_y, 100.0f, 100.0f);
        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_bind_texture(
        creature_type_table[5].texture_handle, 0);
    grim_interface_ptr->grim_set_config_var(0x13, 1u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);

    if (player_state_table[render_overlay_player_index].health <= 0.0f) {
        int frame;
        if (player_state_table[render_overlay_player_index].death_timer
            < 0.0f) {
            frame = 52;
        } else {
            frame = (int)(
                (1.0f
                 - player_state_table[render_overlay_player_index].death_timer
                     * 0.0625f)
                    * 20.0f
                + 32.0f);
        }

        grim_interface_ptr->grim_begin_batch();
        player_render_set_uv(effect_uv8, frame);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, transition_alpha * 0.35f);
        grim_interface_ptr->grim_set_rotation(
            player_state_table[render_overlay_player_index].aim_heading);

        half_size =
            player_state_table[render_overlay_player_index].size * 0.5f;
        render_scratch_f0 =
            camera_offset
            + *(player_render_vec2_t *)&player_state_table
                  [render_overlay_player_index]
                      .pos_x
            - half_size;
        sprite_size =
            player_state_table[render_overlay_player_index].size * 1.03f;
        grim_interface_ptr->grim_draw_quad(
            render_scratch_f0.x + 1.0f,
            render_scratch_f0.y + 1.0f,
            sprite_size,
            sprite_size);
        grim_interface_ptr->grim_end_batch();

        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
        player_render_set_tint(transition_alpha);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            render_scratch_f0.x,
            render_scratch_f0.y,
            player_state_table[render_overlay_player_index].size,
            player_state_table[render_overlay_player_index].size);
        grim_interface_ptr->grim_end_batch();
        return;
    }

    int frame = (int)(
        player_state_table[render_overlay_player_index].move_phase + 0.5f);
    float recoil_heading =
        player_state_table[render_overlay_player_index].aim_heading
        + 1.5707964f;
    player_render_vec2_t recoil(
        (float)cos(recoil_heading)
            * player_state_table[render_overlay_player_index]
                  .muzzle_flash_alpha
            * 12.0f,
        (float)sin(recoil_heading)
            * player_state_table[render_overlay_player_index]
                  .muzzle_flash_alpha
            * 12.0f);

    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, transition_alpha * 0.35f);
    grim_interface_ptr->grim_set_rotation(
        player_state_table[render_overlay_player_index].heading);
    player_render_set_uv(effect_uv8, frame);
    grim_interface_ptr->grim_begin_batch();

    half_size =
        player_state_table[render_overlay_player_index].size * 0.5f - 2.0f;
    render_scratch_f0 =
        camera_offset
        + *(player_render_vec2_t *)&player_state_table
              [render_overlay_player_index]
                  .pos_x
        - half_size;
    sprite_size =
        player_state_table[render_overlay_player_index].size * 1.02f;
    grim_interface_ptr->grim_draw_quad(
        render_scratch_f0.x + 1.0f,
        render_scratch_f0.y + 1.0f,
        sprite_size,
        sprite_size);

    player_render_set_uv(player_overlay_torso_uv8, frame);
    grim_interface_ptr->grim_set_rotation(
        player_state_table[render_overlay_player_index].aim_heading);
    render_scratch_f0 =
        camera_offset
        + *(player_render_vec2_t *)&player_state_table
              [render_overlay_player_index]
                  .pos_x
        - player_render_vec2_t(
            player_state_table[render_overlay_player_index].size * 0.5f,
            player_state_table[render_overlay_player_index].size * 0.5f)
        + recoil;
    sprite_size =
        player_state_table[render_overlay_player_index].size * 1.03f;
    grim_interface_ptr->grim_draw_quad(
        render_scratch_f0.x + 1.0f,
        render_scratch_f0.y + 1.0f,
        sprite_size,
        sprite_size);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_bind_texture(
        creature_type_table[5].texture_handle, 0);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, transition_alpha);
    grim_interface_ptr->grim_set_rotation(
        player_state_table[render_overlay_player_index].heading);
    player_render_set_uv(effect_uv8, frame);

    half_size =
        player_state_table[render_overlay_player_index].size * 0.5f;
    render_scratch_f0 =
        camera_offset
        + *(player_render_vec2_t *)&player_state_table
              [render_overlay_player_index]
                  .pos_x
        - half_size;
    grim_interface_ptr->grim_draw_quad(
        render_scratch_f0.x,
        render_scratch_f0.y,
        player_state_table[render_overlay_player_index].size,
        player_state_table[render_overlay_player_index].size);

    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, transition_alpha);
    if (config_player_count > 1) {
        if (render_overlay_player_index == 0) {
            grim_interface_ptr->grim_set_color(
                0.3f, 0.3f, 1.0f, transition_alpha);
        } else {
            grim_interface_ptr->grim_set_color(
                1.0f, 0.55f, 0.35f, transition_alpha);
        }
    }
    player_render_set_uv(player_overlay_torso_uv8, frame);
    grim_interface_ptr->grim_set_rotation(
        player_state_table[render_overlay_player_index].aim_heading);
    render_scratch_f0 =
        camera_offset
        + *(player_render_vec2_t *)&player_state_table
              [render_overlay_player_index]
                  .pos_x
        - player_render_vec2_t(
            player_state_table[render_overlay_player_index].size * 0.5f,
            player_state_table[render_overlay_player_index].size * 0.5f)
        + recoil;
    grim_interface_ptr->grim_draw_quad(
        render_scratch_f0.x,
        render_scratch_f0.y,
        player_state_table[render_overlay_player_index].size,
        player_state_table[render_overlay_player_index].size);
    grim_interface_ptr->grim_end_batch();

    if (player_state_table[render_overlay_player_index].shield_timer > 0.0f) {
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 2u);
        grim_interface_ptr->grim_bind_texture(particles_texture, 0);
        effect_select_texture(2);

        float shield_strength =
            ((float)sin(game_time_s) + 1.0f) * 0.25
            + player_state_table[render_overlay_player_index].shield_timer;
        if (player_state_table[render_overlay_player_index].shield_timer
            < 1.0f) {
            shield_strength *=
                player_state_table[render_overlay_player_index].shield_timer;
        }
        if (shield_strength > 1.0f) {
            shield_strength = 1.0f;
        }
        shield_strength *= transition_alpha;

        grim_interface_ptr->grim_set_color(
            0.35686275f,
            0.70588237f,
            1.0f,
            shield_strength * 0.4f);

        half_size =
            (float)sin(game_time_s * 3.0f) + 17.5f;
        float effect_heading =
            player_state_table[render_overlay_player_index].aim_heading
            - 1.5707964f;
        effect_offset = player_render_vec2_t(
            (float)cos(effect_heading) * 3.0f,
            (float)sin(effect_heading) * 3.0f);
        grim_interface_ptr->grim_set_rotation(game_time_s + game_time_s);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            camera_offset.x
                + player_state_table[render_overlay_player_index].pos_x
                - half_size + effect_offset.x,
            effect_offset.y
                + player_state_table[render_overlay_player_index].pos_y
                + camera_offset.y - half_size,
            half_size + half_size,
            half_size + half_size);

        grim_interface_ptr->grim_set_color(
            0.35686275f,
            0.70588237f,
            1.0f,
            shield_strength * 0.3f);
        half_size =
            (float)sin(game_time_s * 3.0f) * 4.0f + 24.0f;
        grim_interface_ptr->grim_set_rotation(game_time_s * -2.0f);
        grim_interface_ptr->grim_draw_quad(
            camera_offset.x
                + player_state_table[render_overlay_player_index].pos_x
                - half_size + effect_offset.x,
            effect_offset.y
                + player_state_table[render_overlay_player_index].pos_y
                + camera_offset.y - half_size,
            half_size + half_size,
            half_size + half_size);
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_config_var(0x14, 6u);
    }

    if ((weapon_table[player_state_table[render_overlay_player_index].weapon_id]
             .flags
         & 8)
        == 0) {
        float effect_heading =
            player_state_table[render_overlay_player_index].aim_heading
            + 1.5707964f;
        effect_offset = player_render_vec2_t(
            (float)cos(effect_heading)
                    * player_state_table[render_overlay_player_index]
                          .muzzle_flash_alpha
                    * 12.0f
                - (float)cos(effect_heading) * 21.0f,
            (float)sin(effect_heading)
                    * player_state_table[render_overlay_player_index]
                          .muzzle_flash_alpha
                    * 12.0f
                - (float)sin(effect_heading) * 21.0f);

        grim_interface_ptr->grim_bind_texture(muzzle_flash_texture, 0);
        grim_interface_ptr->grim_set_config_var(0x13, 2u);
        grim_interface_ptr->grim_set_config_var(0x14, 2u);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        float effect_alpha =
            player_state_table[render_overlay_player_index]
                .muzzle_flash_alpha
            * 0.8f;
        if (effect_alpha > 1.0f) {
            effect_alpha = 1.0f;
        }
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, effect_alpha * transition_alpha);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_rotation(
            player_state_table[render_overlay_player_index].aim_heading);

        sprite_size =
            player_state_table[render_overlay_player_index].size;
        if ((weapon_table[
                 player_state_table[render_overlay_player_index].weapon_id]
                 .flags
             & 4)
            != 0) {
            half_size = sprite_size * 0.25f;
            render_scratch_f0 =
                camera_offset
                + *(player_render_vec2_t *)&player_state_table
                      [render_overlay_player_index]
                          .pos_x
                - half_size
                + effect_offset;
            sprite_size =
                player_state_table[render_overlay_player_index].size * 0.5f;
            grim_interface_ptr->grim_draw_quad(
                render_scratch_f0.x,
                render_scratch_f0.y,
                sprite_size,
                sprite_size);
        } else {
            half_size = sprite_size * 0.5f;
            sprite_size =
                player_state_table[render_overlay_player_index].size;
            render_scratch_f0 =
                camera_offset
                + *(player_render_vec2_t *)&player_state_table
                      [render_overlay_player_index]
                          .pos_x
                - half_size
                + effect_offset;
            grim_interface_ptr->grim_draw_quad(
                render_scratch_f0.x,
                render_scratch_f0.y,
                sprite_size,
                sprite_size);
        }
        grim_interface_ptr->grim_end_batch();
    }

    if (perk_count_get(player_overlay_auto_target_line_perk_id)) {
        grim_interface_ptr->grim_set_config_var(0x13, 5u);
        grim_interface_ptr->grim_set_config_var(0x14, 2u);
        grim_interface_ptr->grim_bind_texture(projectile_texture, 0);
        grim_interface_ptr->grim_set_atlas_frame(4, 2);
        grim_interface_ptr->grim_begin_batch();

        player_state_t *line_player = player_state_table;
        for (int player_index = 0;
             player_index < config_player_count;
            ++player_index, ++line_player) {
            if (line_player->player_reserved_98 > 0.25f) {
                if (player_render_distance(
                        *(player_render_vec2_t *)&line_player->position,
                        *(player_render_vec2_t *)&creature_pool
                            [line_player->auto_target]
                                .position)
                    <= 80.0f) {
                    direction.x =
                        creature_pool[line_player->auto_target].pos_x
                        - line_player->pos_x;
                    direction.y =
                        creature_pool[line_player->auto_target].pos_y
                        - line_player->pos_y;
                    float distance = (float)sqrt(
                        direction.y * direction.y
                        + direction.x * direction.x);
                    D3DXVec2Normalize(
                        (vec2f_t *)&direction,
                        (const vec2f_t *)&direction);
                    player_render_vec2_t draw_origin(
                        camera_offset.x + line_player->pos_x - 16.0f,
                        camera_offset.y + line_player->pos_y - 16.0f);
                    grim_interface_ptr->grim_set_color(
                        0.5f, 0.6f, 1.0f, transition_alpha);

                    for (float offset = 0.0f;
                         offset < distance;
                         offset += 8.0f) {
                        grim_interface_ptr->grim_draw_quad(
                            direction.x * offset + draw_origin.x,
                            direction.y * offset + draw_origin.y,
                            32.0f,
                            32.0f);
                    }
                }
            }
        }
        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
}
