extern "C" {
void freeware_bonus_count_global_init();
void freeware_pickup_id_global_init();

void freeware_bonus_count_global_init_thunk()
{
    freeware_bonus_count_global_init();
}

void freeware_pickup_id_global_init_thunk()
{
    freeware_pickup_id_global_init();
}
}
