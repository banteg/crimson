#include <string.h>

#include "crimsonland_audio.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

// The two exact functions immediately before ui_menu_assets_init in the native
// image. Keep each function's independently recovered type constraints intact
// so this probe isolates same-object compilation from type-shape changes.
struct ui_neighbor_vec2_t {
    float x;
    float y;

    ui_neighbor_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    ui_neighbor_vec2_t &operator+=(const ui_neighbor_vec2_t &other)
    {
        float result_x = x + other.x;
        x = result_x;
        y += other.y;
        return *this;
    }
};

struct ui_neighbor_vertex_t {
    ui_neighbor_vec2_t position;
    struct ui_depth_t {
        float z;
        float rhw;
    } depth;
    unsigned int color;
    ui_neighbor_vec2_t uv;
};

struct ui_neighbor_quad_t {
    ui_neighbor_vertex_t vertices[8];
    int texture_handle;
    int quad_mode;
};

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" void ui_element_set_rect(
    ui_menu_item_subtemplate_block_t *element,
    float width,
    float height,
    float *offset)
{
    ui_neighbor_quad_t *quad = (ui_neighbor_quad_t *)element;
    ui_neighbor_vertex_t *vertices = quad->vertices;
    ui_neighbor_vertex_t::ui_depth_t depth;
    float inv_width = 1.0f / width;
    float inv_height = 1.0f / height;
    float right = width - 1.0f;

    vertices[0].position = ui_neighbor_vec2_t(1.0f, 1.0f);
    vertices[1].position = ui_neighbor_vec2_t(right, 1.0f);

    float bottom = height - 1.0f;
    vertices[3].position = ui_neighbor_vec2_t(1.0f, bottom);
    vertices[2].position = ui_neighbor_vec2_t(right, bottom);

    vertices[0].uv = ui_neighbor_vec2_t(inv_width, inv_height);
    vertices[1].uv = ui_neighbor_vec2_t(1.0f - inv_width, inv_height);
    vertices[3].uv = ui_neighbor_vec2_t(inv_width, 1.0f - inv_width);
    vertices[2].uv = ui_neighbor_vec2_t(1.0f - inv_width, 1.0f - inv_height);

    depth.z = 0.5f;
    depth.rhw = 1.0f;
    for (int i = 0; i < 4; ++i) {
        vertices[i].color = 0xffffffff;
        vertices[i].depth = depth;
        vertices[i].position += *(ui_neighbor_vec2_t *)offset;
    }
}

extern "C" void ui_element_load(
    ui_menu_item_subtemplate_block_t *element,
    char *jaz_path)
{
    char texture_name[256];
    strcpy(texture_name, jaz_path);
    texture_name[strlen(jaz_path) - 4] = 0;

    if (cv_silentloads->value == 0.0f) {
        console_printf(
            &console_log_queue,
            "Loading uiElement %s\n",
            texture_name);
    }

    grim_interface_ptr->grim_load_texture(texture_name, jaz_path);
    element->texture_handle =
        grim_interface_ptr->grim_get_texture_handle(texture_name);
    if (element->texture_handle == -1) {
        console_printf(
            &console_log_queue,
            "! FAILED Loading uiElement %s\n",
            texture_name);
    }
}

struct ui_menu_vec2_t {
    float x;
    float y;

    ui_menu_vec2_t()
    {
    }

    ui_menu_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    ui_menu_vec2_t &operator+=(const ui_menu_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct ui_menu_vertex_t {
    ui_menu_vec2_t position;
    float z;
    float rhw;
    unsigned int color;
    float u;
    float v;

    ui_menu_vertex_t()
    {
    }
};

struct ui_menu_template_t {
    ui_menu_vertex_t slots[8];
    int texture_handle;
    int quad_mode;
};

extern "C" ui_menu_template_t ui_sign_crimson_template;
extern "C" ui_menu_template_t ui_menu_item_element;
extern "C" ui_menu_template_t ui_menu_panel_template;
extern "C" ui_menu_template_t ui_menu_item_subtemplate_block_01[6];

extern "C" void ui_menu_layout_init(void);

extern "C" void ui_menu_assets_init(void)
{
    ui_menu_vec2_t offset;

    ui_element_load(
        (ui_menu_item_subtemplate_block_t *)&ui_sign_crimson_template,
        "ui\\ui_signCrimson.jaz");
    offset.x = -577.440002f;
    offset.y = -62.0f;
    ui_element_set_rect(
        (ui_menu_item_subtemplate_block_t *)&ui_sign_crimson_template,
        573.440002f,
        143.360001f,
        &offset.x);

    ui_element_load(
        (ui_menu_item_subtemplate_block_t *)&ui_menu_item_element,
        "ui\\ui_menuItem.jaz");
    offset.x = -72.0f;
    offset.y = -60.0f;
    ui_element_set_rect(
        (ui_menu_item_subtemplate_block_t *)&ui_menu_item_element,
        512.0f,
        64.0f,
        &offset.x);

    ui_element_load(
        (ui_menu_item_subtemplate_block_t *)&ui_menu_panel_template,
        "ui\\ui_menuPanel.jaz");
    offset.x = 20.0f;
    offset.y = -82.0f;
    ui_element_set_rect(
        (ui_menu_item_subtemplate_block_t *)&ui_menu_panel_template,
        512.0f,
        256.0f,
        &offset.x);

    ui_menu_template_t *subtemplates = ui_menu_item_subtemplate_block_01;
    subtemplates[0] = ui_menu_panel_template;
    subtemplates[0].quad_mode = 8;
    subtemplates[0].slots[7] = subtemplates[0].slots[3];
    subtemplates[0].slots[6] = subtemplates[0].slots[2];

    subtemplates[0].slots[2].position.y -= 116.0f;
    subtemplates[0].slots[3].position.y -= 116.0f;
    subtemplates[0].slots[2].v = 0.5078125f;
    subtemplates[0].slots[3].v = 0.5078125f;

    subtemplates[0].slots[4] = subtemplates[0].slots[3];
    subtemplates[0].slots[5] = subtemplates[0].slots[2];
    subtemplates[0].slots[4].position.y += 124.0f;
    subtemplates[0].slots[5].position.y += 124.0f;
    subtemplates[0].slots[4].v = 0.5859375f;
    subtemplates[0].slots[5].v = 0.5859375f;
    subtemplates[0].slots[6].position.y += 124.0f;
    subtemplates[0].slots[7].position.y += 124.0f;

    for (int i = 0; i < 8; ++i) {
        subtemplates[0].slots[i].position += ui_menu_vec2_t(-84.0f, 0.0f);
    }

    subtemplates[1] = subtemplates[0];
    subtemplates[1].slots[4].position.y -= 100.0f;
    subtemplates[1].slots[5].position.y -= 100.0f;
    subtemplates[1].slots[6].position.y -= 100.0f;
    subtemplates[1].slots[7].position.y -= 100.0f;

    ui_menu_layout_init();
}
