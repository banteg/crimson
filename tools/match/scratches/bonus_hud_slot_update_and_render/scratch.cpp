#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct bonus_hud_cvar_t {
    unsigned char reserved_00[0x0c];
    float value;
};

struct bonus_hud_vec2_t {
    float x;
    float y;

    bonus_hud_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }
};

struct bonus_hud_color_t {
    float r;
    float g;
    float b;
    float a;

    bonus_hud_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value)
    {
    }
};

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern bonus_hud_cvar_t *cv_uiSmallIndicators;
extern bonus_hud_slot_t bonus_hud_slot_table[];
extern int ui_hud_panel_texture;
extern int bonus_texture;

void ui_draw_progress_bar(
    float *xy,
    float width,
    float ratio,
    float *rgba);
}

extern "C" void bonus_hud_slot_update_and_render(
    float *y,
    int slot_index,
    float alpha)
{
    bonus_hud_slot_t *slot = &bonus_hud_slot_table[slot_index];
    if (!slot->active) {
        return;
    }

    if (*slot->slide.timer_ptr <= 0.0f) {
        if (!slot->slide.alt_timer_ptr
            || *slot->slide.alt_timer_ptr <= 0.0f) {
            slot->slide.slide_x -= frame_dt * 320.0f;
        } else {
            slot->slide.slide_x += frame_dt * 350.0f;
        }
    } else {
        slot->slide.slide_x += frame_dt * 350.0f;
    }

    if (slot->slide.slide_x > -2.0f) {
        slot->slide.slide_x = -2.0f;
    }

    if (slot->slide.slide_x < -184.0f) {
        int check_index = 15;
        if (slot_index <= check_index) {
            bonus_hud_slot_t *check_slot = &bonus_hud_slot_table[15];
            do {
                if (slot_index != check_index) {
                    if (check_slot->active) {
                        break;
                    }
                } else {
                    slot->active = 0;
                }
                --check_index;
                --check_slot;
            } while (slot_index <= check_index);
        }
        *y += 52.0f;
        return;
    }

    float panel_alpha;
    if (cv_uiSmallIndicators->value != 0.0f) {
        grim_interface_ptr->grim_bind_texture(ui_hud_panel_texture, 0);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        panel_alpha = alpha * 0.7f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            slot->slide.slide_x - 100.0f + 4.0f,
            *y + 5.0f,
            182.0f,
            26.5f);
        grim_interface_ptr->grim_end_batch();
    } else {
        grim_interface_ptr->grim_bind_texture(ui_hud_panel_texture, 0);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        panel_alpha = alpha * 0.7f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            slot->slide.slide_x,
            *y - 11.0f,
            182.0f,
            53.0f);
        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_bind_texture(bonus_texture, 0);
    grim_interface_ptr->grim_set_atlas_frame(4, slot->slide.icon_id);
    grim_interface_ptr->grim_draw_quad(
        slot->slide.slide_x - 1.0f,
        *y,
        32.0f,
        32.0f);
    grim_interface_ptr->grim_end_batch();

    if (cv_uiSmallIndicators->value != 0.0f) {
        if (slot->slide.alt_timer_ptr) {
            {
                bonus_hud_color_t bar_color(
                    0.1f, 0.3f, 0.6f, panel_alpha);
                bonus_hud_vec2_t bar_pos(
                    slot->slide.slide_x + 36.0f,
                    *y + 21.0f - 4.0f - 4.0f);
                ui_draw_progress_bar(
                    (float *)&bar_pos,
                    32.0f,
                    *slot->slide.timer_ptr * 0.05f,
                    (float *)&bar_color);
            }
            {
                bonus_hud_color_t bar_color(
                    0.1f, 0.3f, 0.6f, panel_alpha);
                bonus_hud_vec2_t bar_pos(
                    slot->slide.slide_x + 36.0f,
                    *y + 23.0f - 4.0f);
                ui_draw_progress_bar(
                    (float *)&bar_pos,
                    32.0f,
                    *slot->slide.alt_timer_ptr * 0.05f,
                    (float *)&bar_color);
            }
        } else {
            bonus_hud_color_t bar_color(
                0.1f, 0.3f, 0.6f, panel_alpha);
            bonus_hud_vec2_t bar_pos(
                slot->slide.slide_x + 36.0f,
                *y + 21.0f - 4.0f);
            ui_draw_progress_bar(
                (float *)&bar_pos,
                32.0f,
                *slot->slide.timer_ptr * 0.05f,
                (float *)&bar_color);
        }
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        *y += 52.0f;
        return;
    }

    if (slot->slide.alt_timer_ptr) {
        {
            bonus_hud_color_t bar_color(
                0.1f, 0.3f, 0.6f, panel_alpha);
            bonus_hud_vec2_t bar_pos(
                slot->slide.slide_x + 36.0f,
                *y + 21.0f - 4.0f);
            ui_draw_progress_bar(
                (float *)&bar_pos,
                100.0f,
                *slot->slide.timer_ptr * 0.05f,
                (float *)&bar_color);
        }
        {
            bonus_hud_color_t bar_color(
                0.1f, 0.3f, 0.6f, panel_alpha);
            bonus_hud_vec2_t bar_pos(
                slot->slide.slide_x + 36.0f,
                *y + 23.0f);
            ui_draw_progress_bar(
                (float *)&bar_pos,
                100.0f,
                *slot->slide.alt_timer_ptr * 0.05f,
                (float *)&bar_color);
        }
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        grim_interface_ptr->grim_draw_text_small(
            slot->slide.slide_x + 36.0f,
            *y + 2.0f,
            slot->slide.label);
    } else {
        bonus_hud_color_t bar_color(
            0.1f, 0.3f, 0.6f, panel_alpha);
        bonus_hud_vec2_t bar_pos(
            slot->slide.slide_x + 36.0f,
            *y + 21.0f);
        ui_draw_progress_bar(
            (float *)&bar_pos,
            100.0f,
            *slot->slide.timer_ptr * 0.05f,
            (float *)&bar_color);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        grim_interface_ptr->grim_draw_text_small(
            slot->slide.slide_x + 36.0f,
            *y + 6.0f,
            slot->slide.label);
    }
    *y += 52.0f;
}
