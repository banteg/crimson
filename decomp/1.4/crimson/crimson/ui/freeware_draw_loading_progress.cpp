#include "freeware_ui.h"

using namespace ui140;

extern "C" void freeware_draw_loading_progress(float progress)
{
    scale(.6f);
    tint(1, 1, 1, 1);
    grim_interface_ptr->grim_clear_color(0, 0, 0, 0);
    filter(1);
    bind("crimsonland");
    uv(0, 0, 1, 1);
    tint(1, 1, 1, 1);
    begin();
    quad((float)(viewport_width() / 2 - 256), 50, 512, 512);
    end();

    filter(2);
    bind("bullet");
    uv(0, 0, 1, 1);
    tint(1, 1, 1, .4f);
    begin();
    quad(50, 250, (float)(viewport_width() - 100), 20);
    tint(.38f, .04f, .04f, .9f);
    quad(52, 252, (float)(viewport_width() - 104) * progress, 16);
    end();
    grim_interface_ptr->grim_set_config_var(0x36, true);
}
