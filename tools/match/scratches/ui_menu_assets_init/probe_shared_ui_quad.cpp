#include "crimsonland_ui.h"

// Reuse the recovered type shape from the exact address neighbor
// ui_element_set_rect while retaining the empty default constructors required
// by ui_menu_assets_init's native copy schedule.
struct ui_vec2_t {
    float x;
    float y;

    ui_vec2_t()
    {
    }

    ui_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    ui_vec2_t &operator+=(const ui_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct ui_vertex_t {
    ui_vec2_t position;
    struct ui_depth_t {
        float z;
        float rhw;
    } depth;
    unsigned int color;
    ui_vec2_t uv;

    ui_vertex_t()
    {
    }
};

struct ui_quad_t {
    ui_vertex_t vertices[8];
    int texture_handle;
    int quad_mode;
};

extern "C" ui_quad_t ui_sign_crimson_template;
extern "C" ui_quad_t ui_menu_item_element;
extern "C" ui_quad_t ui_menu_panel_template;
extern "C" ui_quad_t ui_menu_item_subtemplate_block_01[6];

extern "C" void ui_menu_layout_init(void);

extern "C" void ui_menu_assets_init(void)
{
    ui_vec2_t offset;

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

    ui_quad_t *subtemplates = ui_menu_item_subtemplate_block_01;
    subtemplates[0] = ui_menu_panel_template;
    subtemplates[0].quad_mode = 8;
    subtemplates[0].vertices[7] = subtemplates[0].vertices[3];
    subtemplates[0].vertices[6] = subtemplates[0].vertices[2];

    subtemplates[0].vertices[2].position.y -= 116.0f;
    subtemplates[0].vertices[3].position.y -= 116.0f;
    subtemplates[0].vertices[2].uv.y = 0.5078125f;
    subtemplates[0].vertices[3].uv.y = 0.5078125f;

    subtemplates[0].vertices[4] = subtemplates[0].vertices[3];
    subtemplates[0].vertices[5] = subtemplates[0].vertices[2];
    subtemplates[0].vertices[4].position.y += 124.0f;
    subtemplates[0].vertices[5].position.y += 124.0f;
    subtemplates[0].vertices[4].uv.y = 0.5859375f;
    subtemplates[0].vertices[5].uv.y = 0.5859375f;
    subtemplates[0].vertices[6].position.y += 124.0f;
    subtemplates[0].vertices[7].position.y += 124.0f;

    for (int i = 0; i < 8; ++i) {
        subtemplates[0].vertices[i].position += ui_vec2_t(-84.0f, 0.0f);
    }

    subtemplates[1] = subtemplates[0];
    subtemplates[1].vertices[4].position.y -= 100.0f;
    subtemplates[1].vertices[5].position.y -= 100.0f;
    subtemplates[1].vertices[6].position.y -= 100.0f;
    subtemplates[1].vertices[7].position.y -= 100.0f;

    ui_menu_layout_init();
}
