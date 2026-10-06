#include "crimsonland_gameplay.h"

extern "C" ui_element_t *__fastcall ui_element_construct(ui_element_t *element)
{
    element->layers[0].quad_mode = 4;
    element->layers[1].quad_mode = 4;
    element->layers[2].quad_mode = 4;
    element->hover_amount = 0;
    element->direction_flag = 0;
    element->on_update = 0;
    element->on_activate = 0;
    element->active = 0;
    return element;
}
