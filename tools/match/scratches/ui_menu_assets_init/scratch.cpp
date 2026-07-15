#include "crimsonland_ui.h"

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
};

struct ui_menu_template_t {
    ui_menu_vertex_t slots[8];
    int texture_handle;
    int quad_mode;
};

extern "C" ui_menu_template_t ui_sign_crimson_template;
extern "C" ui_menu_template_t ui_menu_item_element;
extern "C" ui_menu_template_t ui_menu_panel_template;
extern "C" ui_menu_template_t ui_menu_item_subtemplate_block_01;
extern "C" ui_menu_template_t ui_menu_item_subtemplate_block_02;

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

    ui_menu_item_subtemplate_block_01 = ui_menu_panel_template;
    ui_menu_item_subtemplate_block_01.quad_mode = 8;
    ui_menu_item_subtemplate_block_01.slots[7] =
        ui_menu_item_subtemplate_block_01.slots[3];
    ui_menu_item_subtemplate_block_01.slots[6] =
        ui_menu_item_subtemplate_block_01.slots[2];

    ui_menu_item_subtemplate_block_01.slots[2].position.y -= 116.0f;
    ui_menu_item_subtemplate_block_01.slots[3].position.y -= 116.0f;
    ui_menu_item_subtemplate_block_01.slots[2].v = 0.5078125f;
    ui_menu_item_subtemplate_block_01.slots[3].v = 0.5078125f;

    ui_menu_item_subtemplate_block_01.slots[4] =
        ui_menu_item_subtemplate_block_01.slots[3];
    ui_menu_item_subtemplate_block_01.slots[5] =
        ui_menu_item_subtemplate_block_01.slots[2];
    ui_menu_item_subtemplate_block_01.slots[4].position.y += 124.0f;
    ui_menu_item_subtemplate_block_01.slots[5].position.y += 124.0f;
    ui_menu_item_subtemplate_block_01.slots[4].v = 0.5859375f;
    ui_menu_item_subtemplate_block_01.slots[5].v = 0.5859375f;
    ui_menu_item_subtemplate_block_01.slots[6].position.y += 124.0f;
    ui_menu_item_subtemplate_block_01.slots[7].position.y += 124.0f;

    for (int i = 0; i < 8; ++i) {
        ui_menu_item_subtemplate_block_01.slots[i].position +=
            ui_menu_vec2_t(-84.0f, 0.0f);
    }

    ui_menu_item_subtemplate_block_02 = ui_menu_item_subtemplate_block_01;
    ui_menu_item_subtemplate_block_02.slots[4].position.y -= 100.0f;
    ui_menu_item_subtemplate_block_02.slots[5].position.y -= 100.0f;
    ui_menu_item_subtemplate_block_02.slots[6].position.y -= 100.0f;
    ui_menu_item_subtemplate_block_02.slots[7].position.y -= 100.0f;

    ui_menu_layout_init();
}
