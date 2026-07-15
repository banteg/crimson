extern "C" void player_state_table_global_init(void);

extern "C" void player_state_table_global_init_thunk(void)
{
    player_state_table_global_init();
}
