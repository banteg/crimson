#ifndef CRIMSON_FREEWARE_ENCOUNTER_CHOICES_H
#define CRIMSON_FREEWARE_ENCOUNTER_CHOICES_H

#include "crimsonland_types.h"
#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int freeware_encounter_hover;
extern vec2f_t freeware_aim_screen;
int freeware_point_in_rect(const vec2f_t *, const vec2f_t *, const vec2f_t *);
}

namespace {
__forceinline void draw_choice_labels(vec2f_t &lo, char **labels, int count) {
    vec2f_t hi;
    freeware_encounter_hover = -1;
    for (int i = 0; i < count; ++i) {
        lo.y = i * 20.0f + 305.0f;
        grim_interface_ptr->grim_set_color(.9f, 1, .7f, .7f);
        float right = lo.x + 250.0f;
        float bottom = lo.y + 15.0f;
        hi.x = right;
        hi.y = bottom;
        if ((unsigned char)freeware_point_in_rect(&freeware_aim_screen, &lo, &hi)) {
            grim_interface_ptr->grim_set_color(.9f, 1, .7f, 1);
            freeware_encounter_hover = i;
        }
        grim_interface_ptr->grim_draw_text_mono(lo.x, lo.y - 5.0f, labels[i]);
    }
}
} // namespace
#endif
