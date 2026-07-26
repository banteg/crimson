#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct ui_layout_vec2_t : vec2f_t {

    ui_layout_vec2_t(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

typedef ui_element_t ui_layout_element_t;

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;

extern int config_screen_width;
extern int config_screen_height;
extern float screen_fade_alpha;
extern float ui_layout_scale_x;
extern float ui_layout_scale_y;
extern unsigned char screen_fade_ramp_flag;
extern unsigned char main_menu_full_version_layout_latch;
extern unsigned char ui_menu_layout_init_latch;
extern ui_element_t *ui_element_hover_focus_ptr;

extern ui_layout_element_t ui_sign_crimson;
extern ui_layout_element_t ui_element_slot_01_main_menu_aux;
extern ui_layout_element_t ui_element_slot_02_main_menu_primary;
extern ui_layout_element_t ui_element_slot_03_main_menu_play_game;
extern ui_layout_element_t ui_element_slot_04_main_menu_options;
extern ui_layout_element_t ui_element_slot_05_main_menu_statistics;
extern ui_layout_element_t ui_element_slot_footer_variant_a;
extern ui_layout_element_t ui_element_slot_footer_variant_b;
extern ui_layout_element_t ui_element_slot_08;
extern ui_layout_element_t ui_element_slot_09;
extern ui_layout_element_t ui_element_slot_10;
extern ui_layout_element_t ui_element_slot_11;
extern ui_layout_element_t ui_element_slot_12_layout_a;
extern ui_layout_element_t ui_element_slot_13;
extern ui_layout_element_t ui_element_slot_14;
extern ui_layout_element_t ui_element_slot_15;
extern ui_layout_element_t ui_element_slot_16;
extern ui_layout_element_t ui_element_slot_17;
extern ui_layout_element_t ui_element_slot_18_layout_b;
extern ui_layout_element_t ui_element_slot_19;
extern ui_layout_element_t ui_element_slot_20;
extern ui_layout_element_t ui_element_slot_21;
extern ui_layout_element_t ui_element_slot_22;
extern ui_layout_element_t ui_element_slot_23;
extern ui_layout_element_t ui_element_slot_24;
extern ui_layout_element_t ui_element_slot_25;
extern ui_layout_element_t ui_element_slot_26;
extern ui_layout_element_t ui_element_slot_27;
extern ui_layout_element_t ui_element_slot_28;
extern ui_layout_element_t ui_element_slot_29;
extern ui_layout_element_t ui_element_slot_30;
extern ui_layout_element_t ui_element_slot_31;
extern ui_layout_element_t ui_element_slot_32_layout_c;
extern ui_layout_element_t ui_element_slot_33;
extern ui_layout_element_t ui_element_slot_34;
extern ui_layout_element_t ui_element_slot_35;
extern ui_layout_element_t ui_element_slot_36;
extern ui_layout_element_t ui_element_slot_37;
extern ui_layout_element_t ui_element_slot_38;
extern ui_layout_element_t ui_element_slot_39;
extern ui_layout_element_t ui_element_slot_40;

extern ui_layout_element_t *ui_element_table_end;
extern ui_layout_element_t *ui_element_table_slot_01_main_menu_aux;
extern ui_layout_element_t *ui_element_table_slot_02_main_menu_primary;
extern ui_layout_element_t *ui_element_table_slot_03_main_menu_play_game;
extern ui_layout_element_t *ui_element_table_slot_04_main_menu_options;
extern ui_layout_element_t *ui_element_table_slot_05_main_menu_statistics;
extern ui_layout_element_t *ui_element_table_slot_06_main_menu_footer_a;
extern ui_layout_element_t *ui_element_table_slot_07_main_menu_footer_b;
extern ui_layout_element_t *ui_element_table_slot_08;
extern ui_layout_element_t *ui_element_table_slot_09;
extern ui_layout_element_t *ui_element_table_slot_10;
extern ui_layout_element_t *ui_element_table_slot_11;
extern ui_layout_element_t *ui_menu_layout_a;
extern ui_layout_element_t *ui_element_table_slot_13;
extern ui_layout_element_t *ui_element_table_slot_14;
extern ui_layout_element_t *ui_element_table_slot_15;
extern ui_layout_element_t *ui_element_table_slot_16;
extern ui_layout_element_t *ui_element_table_slot_17;
extern ui_layout_element_t *ui_menu_layout_b;
extern ui_layout_element_t *ui_element_table_slot_19;
extern ui_layout_element_t *ui_element_table_slot_20;
extern ui_layout_element_t *ui_element_table_slot_21;
extern ui_layout_element_t *ui_element_table_slot_22;
extern ui_layout_element_t *ui_element_table_slot_23;
extern ui_layout_element_t *ui_element_table_slot_24;
extern ui_layout_element_t *ui_element_table_slot_25;
extern ui_layout_element_t *ui_element_table_slot_26;
extern ui_layout_element_t *ui_element_table_slot_27;
extern ui_layout_element_t *ui_element_table_slot_28;
extern ui_layout_element_t *ui_element_table_slot_29;
extern ui_layout_element_t *ui_element_table_slot_30;
extern ui_layout_element_t *ui_element_table_slot_31;
extern ui_layout_element_t *ui_menu_layout_c;
extern ui_layout_element_t *ui_element_table_slot_33;
extern ui_layout_element_t *ui_element_table_slot_34;
extern ui_layout_element_t *ui_element_table_slot_35;
extern ui_layout_element_t *ui_element_table_slot_36;
extern ui_layout_element_t *ui_element_table_slot_37;
extern ui_layout_element_t *ui_element_table_slot_38;
extern ui_layout_element_t *ui_element_table_slot_39;
extern ui_layout_element_t *ui_element_table_start;

extern ui_layout_element_t ui_perk_prompt_element;
extern ui_element_callback_t ui_perk_prompt_on_activate;
extern float perk_prompt_origin_x;
extern float perk_prompt_origin_y;
extern ui_menu_item_subtemplate_block_t ui_perk_prompt_levelup_element;

extern ui_menu_item_subtemplate_block_t ui_sign_crimson_template;
extern ui_menu_item_subtemplate_block_t ui_menu_item_element;
extern ui_menu_item_subtemplate_block_t ui_menu_panel_template;
extern ui_menu_item_subtemplate_block_t ui_menu_item_subtemplate_block_01;
extern ui_menu_item_subtemplate_block_t ui_menu_item_subtemplate_block_02;

extern int ui_item_texts_texture;
extern int ui_text_reaper_texture;
extern int ui_text_controls_texture;
extern int ui_text_pick_perk_texture;
extern int ui_text_well_done_texture;

int texture_get_or_load_alt(char *path);
void ui_element_init_defaults(ui_element_t *element);
void ui_element_layout_calc(ui_element_t *element);
void ui_element_load(
    ui_menu_item_subtemplate_block_t *element,
    char *jaz_path);
void ui_element_set_rect(
    ui_menu_item_subtemplate_block_t *element,
    float width,
    float height,
    float *offset);

void ui_menu_main_click_buy_full_version(void);
void ui_menu_main_click_mods(void);
void ui_menu_main_click_play_game(void);
void ui_menu_main_click_options(void);
void ui_menu_main_click_statistics(void);
void ui_menu_main_click_recheck_full_version(void);
void ui_menu_main_click_quit(void);
void ui_menu_click_back_contextual(void);
void ui_menu_pause_click_main_menu(void);
void ui_menu_pause_click_resume(void);
void options_menu_update(void);
void play_game_menu_update(void);
void controls_menu_update(void);
void quest_select_menu_update(void);
void ui_callback_noop(void);
}

static __forceinline void copy_layer(
    ui_layout_element_t &element,
    const ui_menu_item_subtemplate_block_t &layer)
{
    element.layers[0] = layer;
}

static __forceinline void set_rect(
    ui_layout_element_t &element,
    float width,
    float height,
    float offset_x,
    float offset_y)
{
    ui_layout_vec2_t offset(offset_x, offset_y);
    ui_element_set_rect(
        &element.layers[1],
        width,
        height,
        &offset.x);
}

static __forceinline void set_atlas_row(
    ui_layout_element_t &element,
    int row)
{
    ui_menu_item_subtemplate_block_t &atlas = element.layers[1];
    float top = (float)row * 0.125f;
    float bottom = (float)(row + 1) * 0.125f;
    *(ui_layout_vec2_t *)&atlas.slot_00.u =
        ui_layout_vec2_t(0.0f, top);
    *(ui_layout_vec2_t *)&atlas.slot_01.u =
        ui_layout_vec2_t(1.0f, top);
    *(ui_layout_vec2_t *)&atlas.slot_02.u =
        ui_layout_vec2_t(1.0f, bottom);
    *(ui_layout_vec2_t *)&atlas.slot_03.u =
        ui_layout_vec2_t(0.0f, bottom);
}

static __forceinline void transform_layers(
    ui_layout_element_t **element_ref,
    float scale,
    float shift_x,
    float shift_y)
{
    for (int i = 0; i < 4; ++i) {
        ui_menu_item_subtemplate_slot_t *first =
            (&(*element_ref)->layers[0].slot_00) + i;
        ui_menu_item_subtemplate_slot_t *third =
            (&(*element_ref)->layers[2].slot_00) + i;
        ui_menu_item_subtemplate_slot_t *second =
            (&(*element_ref)->layers[1].slot_00) + i;

        first->x *= scale;
        first->y *= scale;
        third->x *= scale;
        third->y *= scale;
        second->x *= scale;
        second->y *= scale;

        first->x += shift_x;
        third->x += shift_x;
        second->x += shift_x;
        first->y -= shift_y;
        third->y -= shift_y;
        second->y -= shift_y;
    }
}

static __forceinline void transform_narrow_main_menu(void)
{
    for (int i = 0; i < 4; ++i) {
        (&ui_element_table_end->layers[0].slot_00)[i].x *= 0.8f;
        (&ui_element_table_end->layers[0].slot_00)[i].y *= 0.8f;
        (&ui_element_table_end->layers[2].slot_00)[i].x *= 0.8f;
        (&ui_element_table_end->layers[2].slot_00)[i].y *= 0.8f;
        (&ui_element_table_end->layers[1].slot_00)[i].x *= 0.8f;
        (&ui_element_table_end->layers[1].slot_00)[i].y *= 0.8f;

        (&ui_element_table_end->layers[0].slot_00)[i].x += 10.0f;
        (&ui_element_table_end->layers[2].slot_00)[i].x += 10.0f;
        (&ui_element_table_end->layers[1].slot_00)[i].x += 10.0f;
        (&ui_element_table_slot_01_main_menu_aux
            ->layers[0].slot_00)[i].y -= 14.0f;
        (&ui_element_table_slot_01_main_menu_aux
            ->layers[2].slot_00)[i].y -= 14.0f;
        (&ui_element_table_slot_01_main_menu_aux
            ->layers[1].slot_00)[i].y -= 14.0f;
    }
}

static __forceinline void translate_layer(
    ui_menu_item_subtemplate_block_t &layer,
    float x,
    float y)
{
    for (int i = 0; i < 4; ++i) {
        ui_menu_item_subtemplate_slot_t *slot = (&layer.slot_00) + i;
        slot->x += x;
        slot->y += y;
    }
}

extern "C" void ui_menu_layout_init(void)
{
    int i;

    screen_fade_alpha = 0.0f;
    ui_element_hover_focus_ptr = 0;
    screen_fade_ramp_flag = 0;
    ui_layout_scale_x = (float)config_screen_width * 0.0015625f;
    ui_layout_scale_y = (float)config_screen_height * 0.0020833334f;

    memset(ui_element_table, 0, 41 * sizeof(ui_element_t *));
    ui_layout_element_t **table = ui_element_table;

    ui_element_table_end = &ui_sign_crimson;
    ui_element_table_slot_01_main_menu_aux =
        &ui_element_slot_01_main_menu_aux;
    ui_element_table_slot_02_main_menu_primary =
        &ui_element_slot_02_main_menu_primary;
    ui_element_table_slot_03_main_menu_play_game =
        &ui_element_slot_03_main_menu_play_game;
    ui_element_table_slot_04_main_menu_options =
        &ui_element_slot_04_main_menu_options;
    ui_element_table_slot_05_main_menu_statistics =
        &ui_element_slot_05_main_menu_statistics;

    if (!grim_interface_ptr->grim_get_config_var(100)) {
        ui_element_table_slot_07_main_menu_footer_b =
            &ui_element_slot_footer_variant_a;
        ui_element_table_slot_06_main_menu_footer_a =
            &ui_element_slot_footer_variant_b;
    } else {
        ui_element_table_slot_06_main_menu_footer_a =
            &ui_element_slot_footer_variant_a;
        ui_element_table_slot_07_main_menu_footer_b =
            &ui_element_slot_footer_variant_b;
    }

    ui_element_table_slot_31 = &ui_element_slot_31;
    ui_menu_layout_c = &ui_element_slot_32_layout_c;
    ui_element_table_slot_10 = &ui_element_slot_10;
    ui_element_table_slot_11 = &ui_element_slot_11;
    ui_menu_layout_a = &ui_element_slot_12_layout_a;
    ui_element_table_slot_15 = &ui_element_slot_15;
    ui_element_table_slot_16 = &ui_element_slot_16;
    ui_element_table_slot_17 = &ui_element_slot_17;
    ui_element_table_slot_19 = &ui_element_slot_19;
    ui_element_table_slot_20 = &ui_element_slot_20;
    ui_element_table_slot_21 = &ui_element_slot_21;
    ui_element_table_slot_22 = &ui_element_slot_22;
    ui_element_table_slot_23 = &ui_element_slot_23;
    ui_element_table_slot_24 = &ui_element_slot_24;
    ui_element_table_slot_25 = &ui_element_slot_25;
    ui_element_table_slot_26 = &ui_element_slot_26;
    ui_element_table_slot_27 = &ui_element_slot_27;
    ui_element_table_slot_28 = &ui_element_slot_28;
    ui_element_table_slot_29 = &ui_element_slot_29;
    ui_element_table_slot_30 = &ui_element_slot_30;
    ui_element_table_slot_13 = &ui_element_slot_13;
    ui_element_table_slot_14 = &ui_element_slot_14;
    ui_menu_layout_b = &ui_element_slot_18_layout_b;
    ui_element_table_slot_08 = &ui_element_slot_08;
    ui_element_table_slot_09 = &ui_element_slot_09;
    ui_element_table_slot_33 = &ui_element_slot_33;
    ui_element_table_slot_34 = &ui_element_slot_34;
    ui_element_table_slot_35 = &ui_element_slot_35;
    ui_element_table_slot_36 = &ui_element_slot_36;
    ui_element_table_slot_37 = &ui_element_slot_37;
    ui_element_table_slot_38 = &ui_element_slot_38;
    ui_element_table_slot_39 = &ui_element_slot_39;
    ui_element_table_start = &ui_element_slot_40;

    ui_layout_element_t **table_cursor = ui_element_table;
    do {
        ui_element_init_defaults(*table_cursor);
        ++table_cursor;
    } while ((int)table_cursor
        < (int)&ui_perk_prompt_element);

    copy_layer(ui_sign_crimson, ui_sign_crimson_template);
    ui_sign_crimson.pos =
        ui_layout_vec2_t((float)(config_screen_width + 4), 70.0f);
    if (config_screen_width <= 640) {
        ui_sign_crimson.pos.y = 60.0f;
    }

    ui_item_texts_texture =
        texture_get_or_load_alt("ui\\ui_itemTexts.jaz");
    ui_text_reaper_texture =
        texture_get_or_load_alt("ui\\ui_textReaper.jaz");
    ui_text_controls_texture =
        texture_get_or_load_alt("ui\\ui_textControls.jaz");
    ui_text_pick_perk_texture =
        texture_get_or_load_alt("ui\\ui_textPickAPerk.jaz");
    ui_text_well_done_texture =
        texture_get_or_load_alt("ui\\ui_textWellDone.jaz");

    copy_layer(
        ui_element_slot_02_main_menu_primary,
        ui_menu_item_element);
    ui_element_slot_02_main_menu_primary.pos =
        ui_layout_vec2_t(-60.0f, 210.0f);
    set_rect(
        ui_element_slot_02_main_menu_primary,
        124.0f,
        30.0f,
        270.0f,
        -38.0f);
    ui_element_slot_02_main_menu_primary.label_id = 48;
    ui_element_slot_02_main_menu_primary.on_activate =
        ui_menu_main_click_buy_full_version;
    if (game_is_full_version()) {
        ui_element_slot_02_main_menu_primary.on_activate =
            ui_menu_main_click_mods;
    }

    copy_layer(
        ui_element_slot_03_main_menu_play_game,
        ui_menu_item_element);
    ui_element_slot_03_main_menu_play_game.pos =
        ui_layout_vec2_t(-60.0f, 270.0f);
    set_rect(
        ui_element_slot_03_main_menu_play_game,
        124.0f,
        30.0f,
        270.0f,
        -38.0f);
    ui_element_slot_03_main_menu_play_game.on_activate =
        ui_menu_main_click_play_game;
    ui_element_slot_03_main_menu_play_game.label_id = 25;

    copy_layer(
        ui_element_slot_04_main_menu_options,
        ui_menu_item_element);
    ui_element_slot_04_main_menu_options.pos =
        ui_layout_vec2_t(-60.0f, 330.0f);
    set_rect(
        ui_element_slot_04_main_menu_options,
        124.0f,
        30.0f,
        270.0f,
        -38.0f);
    ui_element_slot_04_main_menu_options.on_activate =
        ui_menu_main_click_options;
    ui_element_slot_04_main_menu_options.label_id = 24;

    copy_layer(
        ui_element_slot_05_main_menu_statistics,
        ui_menu_item_element);
    ui_element_slot_05_main_menu_statistics.pos =
        ui_layout_vec2_t(-60.0f, 390.0f);
    set_rect(
        ui_element_slot_05_main_menu_statistics,
        124.0f,
        30.0f,
        270.0f,
        -38.0f);
    ui_element_slot_05_main_menu_statistics.on_activate =
        ui_menu_main_click_statistics;
    ui_element_slot_05_main_menu_statistics.label_id = 31;

    int footer_row = 5;
    if (grim_interface_ptr->grim_get_config_var(100)) {
        copy_layer(
            ui_element_slot_footer_variant_a,
            ui_menu_item_element);
        ui_element_slot_footer_variant_a.pos =
            ui_layout_vec2_t(-60.0f, 450.0f);
        set_rect(
            ui_element_slot_footer_variant_a,
            124.0f,
            30.0f,
            270.0f,
            -38.0f);
        ui_element_slot_footer_variant_a.label_id = 48;
        ui_element_slot_footer_variant_a.on_activate =
            ui_menu_main_click_recheck_full_version;
        footer_row = 6;
    }

    copy_layer(
        ui_element_slot_footer_variant_b,
        ui_menu_item_element);
    ui_element_slot_footer_variant_b.pos = ui_layout_vec2_t(
        -60.0f,
        (float)(footer_row * 60 + 150));
    set_rect(
        ui_element_slot_footer_variant_b,
        124.0f,
        30.0f,
        270.0f,
        -38.0f);
    ui_element_slot_footer_variant_b.on_activate =
        ui_menu_main_click_quit;
    ui_element_slot_footer_variant_b.label_id = 16;

    int atlas_row = 0;
    for (i = 2; i <= 7; ++i) {
        if (i == 2 && game_is_full_version()) {
            atlas_row = 4;
        }

        if (!grim_interface_ptr->grim_get_config_var(100)) {
            if (i == 6) {
                atlas_row = 6;
            }
            table[i]->layers[1].texture_handle = ui_item_texts_texture;
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_00.u =
                ui_layout_vec2_t(0.0f, (float)atlas_row * 0.125f);
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_01.u =
                ui_layout_vec2_t(1.0f, (float)atlas_row * 0.125f);
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_02.u =
                ui_layout_vec2_t(
                    1.0f,
                    (float)(atlas_row + 1) * 0.125f);
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_03.u =
                ui_layout_vec2_t(
                    0.0f,
                    (float)(atlas_row + 1) * 0.125f);
        } else {
            table[i]->layers[1].texture_handle = ui_item_texts_texture;
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_00.u =
                ui_layout_vec2_t(0.0f, (float)atlas_row * 0.125f);
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_01.u =
                ui_layout_vec2_t(1.0f, (float)atlas_row * 0.125f);
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_02.u =
                ui_layout_vec2_t(
                    1.0f,
                    (float)(atlas_row + 1) * 0.125f);
            *(ui_layout_vec2_t *)&table[i]->layers[1].slot_03.u =
                ui_layout_vec2_t(
                    0.0f,
                    (float)(atlas_row + 1) * 0.125f);
        }

        if (i == 2 && game_is_full_version()) {
            atlas_row = 0;
        }
        ++atlas_row;
        if (atlas_row == 4) {
            ++atlas_row;
        }
    }

    if (config_screen_width <= 640) {
        transform_narrow_main_menu();
    } else if (config_screen_width > 800
        && config_screen_width <= 1024) {
        transform_layers(&ui_element_table_end, 1.2f, 10.0f, 0.0f);
    }

    int stagger_x = -20;
    int stagger_time = 100;
    ui_layout_element_t **main_entry =
        &ui_element_table_slot_01_main_menu_aux;
    do {
        (*main_entry)->timeline_start_ms += stagger_time;
        (*main_entry)->timeline_end_ms += stagger_time;
        if (stagger_x > 0) {
            (*main_entry)->pos.x -= (float)stagger_x;
        }
        stagger_x += 20;
        stagger_time += 100;
        ++main_entry;
    } while (stagger_x <= 100);

    if (game_is_full_version()) {
        main_menu_full_version_layout_latch = 1;
    }

    copy_layer(ui_element_slot_31, ui_menu_panel_template);
    ui_element_slot_31.hover_max.x =
        ui_element_slot_31.hover_min.x + 280.0f;
    ui_element_slot_31.hover_max.y =
        ui_element_slot_31.hover_min.y + 180.0f;
    ui_element_slot_31.pos = ui_layout_vec2_t(-45.0f, 210.0f);
    ui_element_slot_31.on_activate = 0;
    ui_element_slot_31.on_update = options_menu_update;
    ui_element_slot_31.use_offset_render = 1;

    copy_layer(ui_element_slot_32_layout_c, ui_menu_item_element);
    ui_element_slot_32_layout_c.pos =
        ui_layout_vec2_t(-55.0f, 430.0f);
    set_rect(
        ui_element_slot_32_layout_c,
        124.0f,
        30.0f,
        270.0f,
        -38.0f);
    ui_element_slot_32_layout_c.layers[1].texture_handle =
        ui_item_texts_texture;
    set_atlas_row(ui_element_slot_32_layout_c, 7);
    ui_element_slot_32_layout_c.on_activate =
        ui_menu_click_back_contextual;
    ui_element_slot_32_layout_c.use_offset_render = 1;
    ui_element_slot_32_layout_c.label_id = 48;

    copy_layer(ui_element_slot_23, ui_menu_item_element);
    ui_element_slot_23.pos = ui_layout_vec2_t(-60.0f, 210.0f);
    ui_element_slot_23.layers[1] =
        ui_element_slot_04_main_menu_options.layers[1];
    ui_element_slot_23.timeline_end_ms += 100;
    ui_element_slot_23.timeline_start_ms += 100;
    ui_element_slot_23.on_activate = ui_menu_main_click_options;

    copy_layer(ui_element_slot_24, ui_menu_item_element);
    ui_element_slot_24.pos = ui_layout_vec2_t(-80.0f, 270.0f);
    ui_element_slot_24.layers[1] =
        ui_element_slot_footer_variant_b.layers[1];
    ui_element_slot_24.on_activate = ui_menu_pause_click_main_menu;
    ui_element_slot_24.timeline_end_ms += 200;
    ui_element_slot_24.timeline_start_ms += 200;

    copy_layer(ui_element_slot_25, ui_menu_item_element);
    ui_element_slot_25.pos = ui_layout_vec2_t(-100.0f, 330.0f);
    ui_element_slot_25.layers[1] =
        ui_element_slot_32_layout_c.layers[1];
    ui_element_slot_25.timeline_end_ms += 300;
    ui_element_slot_25.timeline_start_ms += 300;
    ui_element_slot_25.on_activate = ui_menu_pause_click_resume;
    ui_element_slot_25.label_id = 48;

    ui_element_slot_26.pos = ui_layout_vec2_t(-175.0f, 45.0f);
    ui_element_slot_26.use_offset_render = 1;

    copy_layer(
        ui_element_slot_27,
        ui_menu_item_subtemplate_block_01);
    ui_element_slot_27.pos = ui_layout_vec2_t(-45.0f, 110.0f);
    ui_element_slot_27.timeline_end_ms += 100;
    ui_element_slot_27.timeline_start_ms += 100;
    ui_element_slot_27.use_offset_render = 1;

    ui_element_slot_10.pos = ui_layout_vec2_t(-60.0f, 145.0f);
    ui_element_slot_10.use_offset_render = 1;

    copy_layer(
        ui_element_slot_11,
        ui_menu_item_subtemplate_block_02);
    ui_element_slot_11.pos = ui_layout_vec2_t(-45.0f, 210.0f);
    translate_layer(ui_element_slot_11.layers[1], 10.0f, 10.0f);
    ui_element_slot_11.on_update = play_game_menu_update;
    ui_element_slot_11.use_offset_render = 1;

    copy_layer(ui_element_slot_12_layout_a, ui_menu_item_element);
    ui_element_slot_12_layout_a.pos =
        ui_layout_vec2_t(-55.0f, 462.0f);
    ui_element_slot_12_layout_a.layers[1] =
        ui_element_slot_32_layout_c.layers[1];
    ui_element_slot_12_layout_a.on_activate =
        ui_menu_click_back_contextual;
    ui_element_slot_12_layout_a.use_offset_render = 1;
    ui_element_slot_12_layout_a.label_id = 48;

    ui_element_slot_29.pos = ui_layout_vec2_t(-175.0f, 45.0f);
    ui_element_slot_29.use_offset_render = 1;

    copy_layer(
        ui_element_slot_30,
        ui_menu_item_subtemplate_block_01);
    ui_element_slot_30.pos = ui_layout_vec2_t(-45.0f, 110.0f);
    ui_element_slot_30.timeline_start_ms += 100;
    ui_element_slot_30.timeline_end_ms += 100;
    ui_element_slot_30.use_offset_render = 1;

    ui_element_slot_13.pos = ui_layout_vec2_t(-180.0f, 135.0f);
    ui_element_slot_13.use_offset_render = 1;

    copy_layer(ui_element_slot_14, ui_menu_panel_template);
    ui_element_slot_14.pos.x =
        config_screen_width <= 640 ? -183.0f : -165.0f;
    ui_element_slot_14.pos.y = 200.0f;
    ui_element_slot_14.on_update = controls_menu_update;
    ui_element_slot_14.use_offset_render = 1;

    copy_layer(ui_element_slot_18_layout_b, ui_menu_item_element);
    ui_element_slot_18_layout_b.pos =
        ui_layout_vec2_t(-155.0f, 420.0f);
    ui_element_slot_18_layout_b.layers[1] =
        ui_element_slot_32_layout_c.layers[1];
    ui_element_slot_18_layout_b.on_activate =
        ui_menu_main_click_options;
    ui_element_slot_18_layout_b.use_offset_render = 0;
    ui_element_slot_18_layout_b.label_id = 48;

    ui_element_slot_34.pos = ui_layout_vec2_t(-175.0f, 45.0f);
    ui_element_slot_34.use_offset_render = 1;

    copy_layer(
        ui_element_slot_35,
        ui_menu_item_subtemplate_block_01);
    ui_element_slot_35.pos = ui_layout_vec2_t(-45.0f, 110.0f);
    ui_element_slot_35.timeline_end_ms += 100;
    ui_element_slot_35.timeline_start_ms += 100;
    ui_element_slot_35.use_offset_render = 1;

    ui_element_slot_36.pos = ui_layout_vec2_t(-135.0f, 122.0f);
    ui_element_slot_36.use_offset_render = 1;

    copy_layer(
        ui_element_slot_37,
        ui_menu_item_subtemplate_block_01);
    ui_element_slot_37.pos = ui_layout_vec2_t(-5.0f, 185.0f);
    ui_element_slot_37.on_update = quest_select_menu_update;
    ui_element_slot_37.use_offset_render = 1;

    ui_element_slot_38.pos = ui_layout_vec2_t(-135.0f, 122.0f);
    ui_element_slot_38.use_offset_render = 1;

    copy_layer(
        ui_element_slot_39,
        ui_menu_item_subtemplate_block_01);
    ui_element_slot_39.pos = ui_layout_vec2_t(-5.0f, 185.0f);
    ui_element_slot_39.use_offset_render = 1;

    float right_panel_x = (float)(config_screen_width - 350);
    copy_layer(ui_element_slot_33, ui_menu_panel_template);
    ui_element_slot_33.pos.y = 200.0f;
    if (config_screen_width <= 800) {
        if (config_screen_width <= 640) {
            ui_element_slot_33.pos.x = right_panel_x + 10.0f;
        } else {
            ui_element_slot_33.pos.x = right_panel_x - 30.0f;
        }
    } else {
        ui_element_slot_33.pos.x = right_panel_x - 65.0f;
    }
    ui_element_slot_33.use_offset_render = 1;
    ui_element_slot_33.direction_flag = 1;

    ui_element_slot_08.pos.x =
        config_screen_width <= 640 ? -215.0f : -165.0f;
    ui_element_slot_08.pos.y = 122.0f;
    ui_element_slot_08.use_offset_render = 1;

    copy_layer(
        ui_element_slot_09,
        ui_menu_item_subtemplate_block_01);
    ui_element_slot_09.pos.x =
        config_screen_width <= 640 ? -85.0f : -35.0f;
    ui_element_slot_09.pos.y = 185.0f;
    ui_element_slot_09.use_offset_render = 1;
    ui_element_slot_28.timeline_end_ms = 500;

    int menu_shift = -11;
    ui_layout_element_t **responsive =
        &ui_element_table_slot_01_main_menu_aux;
    do {
        if (config_screen_width <= 640) {
            transform_layers(
                responsive,
                0.9f,
                0.0f,
                (float)menu_shift);
        }
        menu_shift += 11;
        ++responsive;
    } while (menu_shift <= 55);

    int narrow_shift = -11;
    int medium_shift = -5;
    responsive = &ui_element_table_slot_22;
    do {
        if (config_screen_width <= 640) {
            transform_layers(
                responsive,
                0.8f,
                0.0f,
                (float)narrow_shift);
        } else if (config_screen_width <= 800) {
            transform_layers(
                responsive,
                0.9f,
                0.0f,
                (float)medium_shift);
        }
        narrow_shift += 11;
        medium_shift += 5;
        ++responsive;
    } while (narrow_shift <= 22);

    if (config_screen_width <= 640) {
        transform_layers(&ui_menu_layout_c, 0.8f, 0.0f, 11.0f);
    } else if (config_screen_width <= 800) {
        transform_layers(&ui_menu_layout_c, 0.9f, 0.0f, 3.0f);
    }
    if (config_screen_width <= 640) {
        transform_layers(&ui_menu_layout_a, 0.8f, 0.0f, 11.0f);
    } else if (config_screen_width <= 800) {
        transform_layers(&ui_menu_layout_a, 0.9f, 0.0f, 3.0f);
    }
    if (config_screen_width <= 640) {
        transform_layers(&ui_menu_layout_b, 0.8f, 0.0f, 11.0f);
    } else if (config_screen_width <= 800) {
        transform_layers(&ui_menu_layout_b, 0.9f, 0.0f, 3.0f);
    }

    ui_element_init_defaults(&ui_perk_prompt_element);
    ui_perk_prompt_on_activate = ui_callback_noop;
    copy_layer(ui_perk_prompt_element, ui_menu_item_element);
    ui_perk_prompt_element.layers[0].slot_00.u = 1.0f;
    ui_perk_prompt_element.layers[0].slot_01.u = 0.0f;
    ui_perk_prompt_element.layers[0].slot_02.u = 0.0f;
    ui_perk_prompt_element.layers[0].slot_03.u = 1.0f;

    ui_element_load(
        &ui_perk_prompt_levelup_element,
        "ui\\ui_textLevelUp.jaz");
    {
        ui_layout_vec2_t levelup_offset(-230.0f, -27.0f);
        ui_element_set_rect(
            &ui_perk_prompt_levelup_element,
            75.0f,
            25.0f,
            &levelup_offset.x);
    }

    for (i = 0; i < 4; ++i) {
        ui_menu_item_subtemplate_slot_t *prompt_slot =
            (&ui_perk_prompt_element.layers[0].slot_00) + i;
        prompt_slot->x -= 300.0f;
        prompt_slot->x *= 0.75f;
        prompt_slot->y *= 0.75f;

        ui_menu_item_subtemplate_slot_t *levelup_slot =
            (&ui_perk_prompt_levelup_element.slot_00) + i;
        levelup_slot->x *= 0.85f;
        levelup_slot->y *= 0.85f;
        levelup_slot->x -= 46.0f;
        levelup_slot->y -= 4.0f;
    }

    if (config_screen_width == 640) {
        perk_prompt_origin_x = 690.0f;
        perk_prompt_origin_y = 80.0f;
    } else {
        perk_prompt_origin_x = (float)(config_screen_width + 50);
        perk_prompt_origin_y = 40.0f;
    }

    responsive = &ui_element_table_slot_01_main_menu_aux;
    do {
        (*responsive)->pos.y =
            (float)config_screen_width * 0.0015625f * 150.0f
            - 150.0f
            + (*responsive)->pos.y;
        ++responsive;
    } while ((int)responsive < (int)&ui_perk_prompt_element);

    ui_element_slot_40 = ui_element_slot_09;
    ui_element_slot_40.pos =
        ui_layout_vec2_t((float)(config_screen_width - 350), 200.0f);
    if (config_screen_width <= 640) {
        ui_element_slot_40.pos.x += 80.0f;
        ui_element_slot_40.pos.y -= 14.0f;
    }
    ui_element_slot_40.use_offset_render = 1;
    ui_menu_layout_init_latch = 1;

    table = ui_element_table;
    do {
        ui_element_layout_calc(*table);
        ++table;
    } while ((int)table < (int)&ui_perk_prompt_element);
}
