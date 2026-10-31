// 0x404ee0. The wall list is the middle object layer of the level.
#include "freeware_level.h"

static inline bool within(const freeware_level_object &wall, const vec2f_t &p, float r) {
    return p.x >= wall.position.x - r && p.x <= wall.position.x + wall.width + r && p.y >= wall.position.y - r &&
           p.y <= wall.position.y + wall.height + r;
}
int freeware_level_map::move_with_collision(vec2f_t *pos, const vec2f_t *delta, float radius) {
    int blocked = 0;
    pos->x += delta->x;
    pos->y += delta->y;
    for (unsigned i = 0; layers[1].begin && i < (unsigned)(layers[1].end - layers[1].begin); ++i) {
        const freeware_level_object &wall = *layers[1].begin[i];
        if (!within(wall, *pos, radius))
            continue;
        pos->y -= delta->y;
        bool x_inside = within(wall, *pos, radius);
        pos->y += delta->y;
        pos->x -= delta->x;
        bool y_inside = within(wall, *pos, radius);
        if (x_inside)
            blocked |= y_inside ? 1 : 2;
        else if (y_inside) {
            pos->y -= delta->y;
            pos->x += delta->x;
            blocked |= 2;
        } else if (!(blocked & 1))
            pos->x += delta->x;
    }
    return blocked;
}
