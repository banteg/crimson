#include "crimsonland_console.h"

typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

struct ui_vec2_t {
    float x;
    float y;

    ui_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

};

extern "C" void ui_element_init_defaults(ui_element_t *element)
{
    if (element == 0) {
        console_printf(&console_log_queue, "!!! Elem == NULL!\n");
        return;
    }

    element->texture_handle = -1;
    element->overlay_texture_handle = -1;
    element->secondary_overlay_texture_handle = -1;
    *(ui_vec2_t *)&element->hover_min_x = ui_vec2_t(233.0f, 28.0f);
    element->time_since_ready = 256;
    element->on_activate = 0;
    element->on_update = 0;
    *(ui_vec2_t *)&element->hover_max_x = ui_vec2_t(431.0f, 68.0f);
    element->render_scale = 0.0f;
    element->active = 0;
    element->label_id = 57;
    element->hover_enter_played = 0;
    element->timeline_end_ms = 300;
    element->timeline_start_ms = 0;
    element->focus_disabled = 0;
    element->use_offset_render = 0;
}
