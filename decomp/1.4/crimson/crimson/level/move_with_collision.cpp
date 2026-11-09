// Slide a moving circle against the level's wall layer.
#include "freeware_level.h"

static __forceinline bool within(const freeware_level_object &wall, const vec2f_t &p, float radius) {
    return p.x >= wall.position.x - radius && p.x <= wall.position.x + wall.width + radius &&
           p.y >= wall.position.y - radius && p.y <= radius + wall.height + wall.position.y;
}

int freeware_level_map::move_with_collision(vec2f_t *pos, const vec2f_t *delta, float radius) {
    int blocked = 0;
    pos->x += delta->x;
    pos->y += delta->y;
    for (unsigned i = 0; i < layers[1].size(); ++i) {
        const freeware_level_object &wall = *layers[1][i];
        if (!within(wall, *pos, radius))
            continue;
        pos->y -= delta->y;
        if (within(wall, *pos, radius)) {
            pos->y += delta->y;
            pos->x -= delta->x;
            if (within(wall, *pos, radius))
                blocked |= 1;
            else
                blocked |= 2;
        } else {
            pos->y += delta->y;
            pos->x -= delta->x;
            if (!within(wall, *pos, radius)) {
                if (!(blocked & 1))
                    pos->x += delta->x;
            } else {
                pos->y -= delta->y;
                pos->x += delta->x;
                blocked |= 2;
            }
        }
        if (blocked == 4)
            return blocked;
    }
    return blocked;
}
