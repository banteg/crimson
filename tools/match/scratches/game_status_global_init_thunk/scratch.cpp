extern "C" void game_status_global_init(void);

extern "C" void game_status_global_init_thunk(void)
{
    game_status_global_init();
}
