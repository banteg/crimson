#ifndef CRIMSONLAND_UI_H
#define CRIMSONLAND_UI_H

typedef struct ui_element_t ui_element_t;

extern unsigned char ui_mouse_blocked;
extern float ui_mouse_x;
extern float ui_mouse_y;
extern ui_element_t *ui_element_table_end;
extern ui_element_t ui_perk_prompt_element;
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

#ifdef __cplusplus
}
#endif

#endif
