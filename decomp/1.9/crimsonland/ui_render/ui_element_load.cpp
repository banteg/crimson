#include <string.h>

#include "crimsonland_audio.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

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
