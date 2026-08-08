#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

struct ui_render_vec2_t {
    float x;
    float y;
};

struct ui_render_matrix_t {
    float m00;
    float m01;
    float m10;
    float m11;
};

struct ui_point_filter_cvar_t {
    char *name;
    ui_point_filter_cvar_t *next;
    int unknown_08;
    float value;
};

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern ui_point_filter_cvar_t *cv_uiPointFilterPanels;
extern unsigned char console_open_flag;

unsigned char ui_focus_update(int id);
}

static __inline float *ui_element_quad(
    ui_element_t *element,
    int vertex_index)
{
    return &element->vertices[vertex_index].x;
}

static __inline float *ui_element_counter_quad(ui_element_t *element)
{
    return &element->overlay_vertices[0].x;
}

extern "C" void ui_element_render(ui_element_t *element)
{
    unsigned char focused = 0;
    if (!element->active) {
        return;
    }

    if (element->render_scale == 0.0f
        && cv_uiPointFilterPanels->value != 0.0f) {
        grim_interface_ptr->grim_set_config_var(0x15, 1u);
    }

    if (element->on_activate && element != &ui_perk_prompt_element) {
        focused = ui_focus_update((int)element);
        if (focused
            && grim_interface_ptr->grim_was_key_pressed(0x1c)
            && !console_open_flag
            && element->enabled) {
            ui_element_callback_t on_activate = element->on_activate;
            if (on_activate) {
                on_activate();
            }
        }
    }

    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_rotation(0.0f);

    if (element->overlay_texture_handle != -1) {
        if (focused && ui_focus_timer_ms > 0) {
            element->hover_amount = ui_focus_timer_ms;
        }
        if (!element->on_activate) {
            unsigned char *color_alpha =
                &element->overlay_vertices[0].color_a;
            for (int vertex = 0; vertex < 4; ++vertex) {
                *color_alpha = 200;
                color_alpha += sizeof(ui_element_vertex_t);
            }
        } else {
            ui_element_vertex_t *vertex_cursor =
                &element->overlay_vertices[0];
            int remaining_vertices = 4;
            do {
                (vertex_cursor++)->color_a =
                    (unsigned char)(
                        element->hover_amount * 155 / 1000 + 100);
                --remaining_vertices;
            } while (remaining_vertices);
        }
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);

    int texture_handle = element->texture_handle;
    if (texture_handle != -1) {
        grim_interface_ptr->grim_bind_texture(texture_handle, 0);
        unsigned long shadow_color = 0x44444444;

        if (element->use_offset_render == 0) {
            if (config_blob.shadows_enabled) {
                grim_interface_ptr->grim_set_config_var(0x13, 1u);
                grim_interface_ptr->grim_begin_batch();

                ui_render_vec2_t shadow_pos;
                shadow_pos.x = element->pos_x + 7.0f;
                shadow_pos.y = element->pos_y + 7.0f;
                grim_interface_ptr->grim_submit_vertices_transform_color(
                    ui_element_quad(element, 0),
                    4,
                    &shadow_pos.x,
                    &element->rot_m00,
                    &shadow_color);
                if (element->vertex_count == 8) {
                    shadow_pos.x = element->pos_x + 7.0f;
                    shadow_pos.y = element->pos_y + 7.0f;
                    grim_interface_ptr->grim_submit_vertices_transform_color(
                        ui_element_quad(element, 2),
                        4,
                        &shadow_pos.x,
                        &element->rot_m00,
                        &shadow_color);
                    shadow_pos.x = element->pos_x + 7.0f;
                    shadow_pos.y = element->pos_y + 7.0f;
                    grim_interface_ptr->grim_submit_vertices_transform_color(
                        ui_element_quad(element, 4),
                        4,
                        &shadow_pos.x,
                        &element->rot_m00,
                        &shadow_color);
                }
                grim_interface_ptr->grim_end_batch();
            }

            grim_interface_ptr->grim_set_config_var(0x13, 5u);
            grim_interface_ptr->grim_begin_batch();
            grim_interface_ptr->grim_submit_vertices_transform(
                ui_element_quad(element, 0),
                4,
                &element->pos_x,
                &element->rot_m00);
            if (element->vertex_count == 8) {
                grim_interface_ptr->grim_submit_vertices_transform(
                    ui_element_quad(element, 2),
                    4,
                    &element->pos_x,
                    &element->rot_m00);
                grim_interface_ptr->grim_submit_vertices_transform(
                    ui_element_quad(element, 4),
                    4,
                    &element->pos_x,
                    &element->rot_m00);
            }
            grim_interface_ptr->grim_end_batch();
        } else if (element->use_offset_render == 1) {
            if (config_blob.shadows_enabled) {
                grim_interface_ptr->grim_set_config_var(0x13, 1u);
                grim_interface_ptr->grim_begin_batch();

                ui_render_vec2_t shadow_pos;
                shadow_pos.x = element->pos_x + 7.0f;
                shadow_pos.y = element->pos_y + 7.0f;
                shadow_pos.x += element->render_offset_x;
                shadow_pos.y += element->render_offset_y;
                grim_interface_ptr->grim_submit_vertices_offset_color(
                    ui_element_quad(element, 0),
                    4,
                    &shadow_pos.x,
                    &shadow_color);
                if (element->vertex_count == 8) {
                    shadow_pos.x = element->pos_x + 7.0f;
                    shadow_pos.y = element->pos_y + 7.0f;
                    shadow_pos.x += element->render_offset_x;
                    shadow_pos.y += element->render_offset_y;
                    grim_interface_ptr->grim_submit_vertices_offset_color(
                        ui_element_quad(element, 2),
                        4,
                        &shadow_pos.x,
                        &shadow_color);
                    shadow_pos.x = element->pos_x + 7.0f;
                    shadow_pos.y = element->pos_y + 7.0f;
                    shadow_pos.x += element->render_offset_x;
                    shadow_pos.y += element->render_offset_y;
                    grim_interface_ptr->grim_submit_vertices_offset_color(
                        ui_element_quad(element, 4),
                        4,
                        &shadow_pos.x,
                        &shadow_color);
                }
                grim_interface_ptr->grim_end_batch();
            }

            grim_interface_ptr->grim_set_config_var(0x13, 5u);
            grim_interface_ptr->grim_begin_batch();
            ui_render_vec2_t render_pos;
            render_pos.x =
                element->render_offset_x + element->pos_x;
            render_pos.y =
                element->render_offset_y + element->pos_y;
            grim_interface_ptr->grim_submit_vertices_offset(
                ui_element_quad(element, 0), 4, &render_pos.x);
            if (element->vertex_count == 8) {
                render_pos.x =
                    element->render_offset_x + element->pos_x;
                render_pos.y =
                    element->render_offset_y + element->pos_y;
                grim_interface_ptr->grim_submit_vertices_offset(
                    ui_element_quad(element, 2), 4, &render_pos.x);
                render_pos.x =
                    element->render_offset_x + element->pos_x;
                render_pos.y =
                    element->render_offset_y + element->pos_y;
                grim_interface_ptr->grim_submit_vertices_offset(
                    ui_element_quad(element, 4), 4, &render_pos.x);
            }
            grim_interface_ptr->grim_end_batch();
        }
    }

    int counter_id = element->overlay_texture_handle;
    if (counter_id != -1) {
        grim_interface_ptr->grim_bind_texture(counter_id, 0);
        grim_interface_ptr->grim_begin_batch();
        if (!element->use_offset_render) {
            grim_interface_ptr->grim_submit_vertices_transform(
                ui_element_counter_quad(element),
                4,
                &element->pos_x,
                &element->rot_m00);
        } else {
            ui_render_vec2_t render_pos;
            render_pos.x =
                element->render_offset_x + element->pos_x;
            render_pos.y =
                element->render_offset_y + element->pos_y;
            grim_interface_ptr->grim_submit_vertices_offset(
                ui_element_counter_quad(element), 4, &render_pos.x);
        }
        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 2u);

    if (element->time_since_ready >= 0
        && element->time_since_ready <= 0xff) {
        unsigned char *enabled_alpha =
            &element->enabled_overlay_vertices[0].color_a;
        int remaining_vertices = 4;
        do {
            *(enabled_alpha
              - sizeof(ui_menu_item_subtemplate_block_t)) =
                (unsigned char)(
                    255 - element->time_since_ready / 2);
            --remaining_vertices;
            *enabled_alpha = (unsigned char)(
                255 - element->time_since_ready / 2);
            enabled_alpha += sizeof(ui_element_vertex_t);
        } while (remaining_vertices);
    }

    ui_render_matrix_t rotation =
        *(ui_render_matrix_t *)&element->rot_m00;

    if (element->enabled) {
        int enabled_counter_id = element->overlay_texture_handle;
        if (enabled_counter_id != -1 && element->on_activate) {
            grim_interface_ptr->grim_bind_texture(enabled_counter_id, 0);
            grim_interface_ptr->grim_begin_batch();
            grim_interface_ptr->grim_submit_vertices_transform(
                ui_element_counter_quad(element),
                4,
                &element->pos_x,
                &rotation.m00);
            grim_interface_ptr->grim_end_batch();
        }
    }

    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    ui_element_callback_t on_update = element->on_update;
    if (on_update) {
        on_update();
    }
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
}
