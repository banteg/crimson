#ifndef FREEWARE_LEVEL_H
#define FREEWARE_LEVEL_H

#include "crimsonland_types.h"

struct freeware_level_object {
    vec2f_t position;
    float rotation, width, height;
};

struct freeware_level_map {
    vec2f_t start;
    float start_heading;
    unsigned char prefix[0x28 - 0x0c];
    freeware_level_object **walls_begin, **walls_end;
    int move_with_collision(vec2f_t *pos, const vec2f_t *delta, float radius);
};

extern "C" freeware_level_map *freeware_current_map;
#endif
