#ifndef FREEWARE_EDITOR_BRUSH_H
#define FREEWARE_EDITOR_BRUSH_H

#include "freeware_level.h"
#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern std::vector<freeware_level_object *> freeware_brushes;
}

inline void set_brush_color(effect_color_t &color, float value)
{
    color.a = value;
    color.b = value;
    color.g = value;
    color.r = value;
}

struct freeware_editor_brush : freeware_level_object {
    freeware_editor_brush(char *name, float width_px, float height_px)
    {
        flags = 0;
        rotation = 0;
        width = width_px;
        height = height_px;
        texture = grim_interface_ptr->grim_get_texture_handle(name);
        set_brush_color(color, 1.0f);
    }
};

#endif
