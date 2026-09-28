extern "C" void creature_spawn_slot_table_global_init(void);

extern "C" void creature_spawn_slot_table_global_init_thunk(void)
{
    creature_spawn_slot_table_global_init();
}
