#include "crimsonland_types.h"

extern "C" int freeware_point_in_rect(const vec2f_t *point, const vec2f_t *lo, const vec2f_t *hi)
{
    if (point->x > lo->x && point->y > lo->y && point->x < hi->x && point->y < hi->y)
        return 1;
    return 0;
}
