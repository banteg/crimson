// crimson.exe 1.4.0, 0x404d70.
#include "../crimson/render/world_render.h"
#include "freeware_level.h"
#include <math.h>

using namespace world140;
void freeware_level_map::render_layer(int layer, unsigned char preserve_color) {
    int bound = 0;
    world_uv(0, 0, 1, 1);
    begin();
    for (unsigned i = 0; i < (unsigned)layers[layer].size(); ++i) {
        int previous = bound;
        const freeware_level_object &o = *layers[layer].begin[i];
        bound = o.texture;
        if (!preserve_color) {

            // The original reads the blue component for both green and blue.
            if (o.flags & 1)
                world_tint(o.color.r, o.color.b, o.color.b,
                           ((float)sin(freeware_simulation_clock + freeware_simulation_clock) + 1) * .25f + .5f);
            else
                world_tint(o.color.r, o.color.b, o.color.b, o.color.a);
        }
        if (o.flags & 2)
            world_angle(freeware_simulation_clock + freeware_simulation_clock + o.rotation);
        else
            world_angle(o.rotation);
        if (previous != bound) {
#ifdef CRIMSON_FREEWARE_CLIENT
            for (const auto &brush : UI_GAME.brushes)
                if (brush.object.texture == bound) {
                    bind(brush.name.c_str());
                    break;
                }
#else
            grim_interface_ptr->grim_flush_batch();
            grim_interface_ptr->grim_bind_texture(bound, 0);
#endif
        }
        world_quad(CAMERA.x + o.position.x, CAMERA.y + o.position.y, o.width, o.height);
    }
    end();
}
