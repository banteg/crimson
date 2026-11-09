extern "C" {
extern int freeware_bonus_count, freeware_bonus_time;
extern int freeware_pickup_id, freeware_no_pickup;

void freeware_bonus_count_global_init()
{
    freeware_bonus_count = freeware_bonus_time;
}

void freeware_pickup_id_global_init()
{
    freeware_pickup_id = freeware_no_pickup;
}
}
