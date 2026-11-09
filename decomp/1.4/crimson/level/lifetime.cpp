#include "freeware_level.h"

freeware_level_map::freeware_level_map()
{
    start_heading = 0.0f;
    const vec2f_t center = {320.0f, 200.0f};
    start = center;
    flag = 1;
}

freeware_level_map::~freeware_level_map()
{
    clear();
}
