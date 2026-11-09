#include "crimsonland_types.h"

extern "C" {
extern int freeware_bonus_count, freeware_bonus_time;
extern int freeware_pickup_id, freeware_no_pickup;
extern vec2f_t freeware_pickup_position;

void freeware_bonus_count_global_init()
{
    freeware_bonus_count = freeware_bonus_time;
}

void freeware_pickup_id_global_init()
{
    freeware_pickup_id = freeware_no_pickup;
}

void freeware_pickup_position_global_init()
{
    freeware_pickup_position.x = 0.0f;
    freeware_pickup_position.y = 0.0f;
}
}
