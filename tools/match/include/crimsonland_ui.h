#ifndef CRIMSONLAND_UI_H
#define CRIMSONLAND_UI_H

#include "crimsonland_types.h"

typedef struct ui_element_t ui_element_t;
typedef struct ui_menu_item_subtemplate_block_t ui_menu_item_subtemplate_block_t;

extern unsigned char ui_mouse_blocked;
extern float ui_mouse_x;
extern float ui_mouse_y;
extern ui_element_t *ui_element_table_end;
extern ui_element_t ui_perk_prompt_element;
extern ui_element_t ui_element_slot_26;
extern ui_element_t ui_element_slot_27;
extern int ui_focus_candidates[];
extern int ui_focus_count;
extern int ui_focus_index;
extern int ui_focus_timer_ms;

#ifdef __cplusplus
extern "C" {
#endif

void ui_focus_set(int id, char reset_timer);
int ui_get_element_index(ui_element_t *element);
int ui_mouse_inside_rect(float *xy, int h, int w);
int ui_mouse_inside_rect_with_padding(float *xy, int h, int w);
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

#ifdef __cplusplus
}
#endif

#endif
